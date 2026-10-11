package emitter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/srek3s/sentinel/internal/worker"
)

// DefaultTimeout is the per-request deadline for one POST.
//
// Strict, and set on the http.Client rather than derived from a context deadline,
// so it holds even if a caller passes a context with no deadline. AGENTS.md §3.2
// requires every blocking operation to be context-bounded; a timeout configured
// only on the caller's context would be one `context.Background()` away from
// unbounded.
//
// It MUST exceed the agent's worst-case service time (see [AgentMaxServiceTime]),
// and this value previously did not: it was 5s against an agent that makes two
// sequential LLM calls of up to 60s each on the Tier-2 path. Every Tier-2 request
// therefore timed out client-side, was retried up to DefaultMaxAttempts, and
// escalated — while the agent burned a threadpool thread for up to two minutes.
// The failure is silent: the incident is delivered, the verdict is discarded.
const DefaultTimeout = 130 * time.Second

// AgentMaxServiceTime is the upper bound on the agent's worst-case time to first
// response body byte, as a cross-language contract.
//
// agent/llm.py LLM_TIMEOUT_SECONDS is 60s per model call, and
// agent/triage.py's Tier-2 path makes two sequential calls (_narrative_overlay,
// then _model_rca_section) plus retry sleeps. 120s of model time plus overhead is
// the figure; DefaultTimeout carries 10s of headroom on top.
//
// If either side changes, change both. TestEmitterTimeoutExceedsAgentWorstCase
// in emitter_test.go pins the Go half against this constant.
const AgentMaxServiceTime = 120 * time.Second

// IncidentsPath is the canonical wire endpoint (ARCH §4, agent/main.py
// TRIAGE_PATH).
const IncidentsPath = "/v1/incidents"

// MaxResponseBody bounds how much of a response body is read before giving up.
//
// The agent's success path returns a small JSON verdict, but a misrouted proxy
// returning an HTML error page would otherwise be read into memory in full. 64 KiB
// is far more than any legitimate response and small enough to be a non-issue.
const MaxResponseBody = 64 << 10

// DefaultMaxAttempts bounds the total number of POSTs for one incident, including
// the first.
//
// Two retries covers the realistic transient case - a 429 from the agent's load
// shedding, and one apiserver-side blip - without letting a three-worker pool
// spend its lifetime on a single incident while live ones queue behind it.
const DefaultMaxAttempts = 3

// Base backoff for the 429 retry. Jittered per attempt; see retryDelay.
const baseRetryDelay = 250 * time.Millisecond

// Config configures a [Client].
type Config struct {
	// BaseURL is the agent's root, e.g. "http://srek3s-agent:8000". No path:
	// the client appends [IncidentsPath] itself, so a value carrying one yields
	// ".../v1/incidents/v1/incidents".
	BaseURL string

	// Timeout overrides [DefaultTimeout].
	Timeout time.Duration

	// MaxAttempts overrides [DefaultMaxAttempts].
	MaxAttempts int

	// HTTPClient overrides the constructed client. Tests use it; production
	// leaves it nil so the timeout above is actually applied.
	HTTPClient *http.Client

	// Now supplies the detection instant used for `detection_latency_ms`.
	Now func() time.Time

	// Events converts a scrubbed incident's event messages into wire events. See
	// BuildOptions.Events.
	Events func(*worker.Incident) []ClusterEvent

	// SentinelVersion is this binary's version.
	SentinelVersion string
}

// Client is a worker.Sink that ships incidents to the agent.
//
// Implements [worker.Sink], so it drops into the existing pool with no change
// above it: the pool already treats a Dispatch error as a failed incident and
// counts it. That is the right place for the policy, because the pool's worker
// goroutine is already bounded and already has a per-incident timeout - a retry
// loop here cannot outlive the worker that called it.
type Client struct {
	baseURL      string
	incidentsURL string
	http         *http.Client
	maxAttempts  int
	// timeout is the effective per-attempt deadline, resolved in New and stored
	// here rather than read back off c.http.Timeout at call time. An injected
	// HTTPClient may legitimately carry Timeout == 0 (meaning "no client-level
	// deadline", e.g. httptest's client), and context.WithTimeout(ctx, 0)
	// returns an ALREADY-cancelled context - so every attempt would fail
	// instantly with "context deadline exceeded" and no incident could ever be
	// delivered. Reading the timeout off the client instead of the resolved
	// config value is what introduced that.
	timeout       time.Duration
	now           func() time.Time
	events        func(*worker.Incident) []ClusterEvent
	version       string
	ownsTransport bool
	// sleep pauses for d or until ctx is done, reporting whether the pause ran
	// to completion. Injectable so a test can count backoffs deterministically:
	// retryDelay is full-jitter, so its *duration* is ~uniform in [0, ceiling)
	// and is not a deterministic signal, but whether it was invoked at all is -
	// and that is exactly the property the transport-failure retry test asserts.
	// The production value is timerSleep.
	sleep func(context.Context, time.Duration) bool
}

// Compile-time proof that the emitter is a valid sink. A signature drift in
// worker.Sink would otherwise surface at the New() call in main, which is a
// runtime wiring mistake rather than a compile error at the definition.
var _ worker.Sink = (*Client)(nil)

// New builds a Client.
//
// Fails on an unusable base URL rather than deferring the failure to the first
// incident: a misconfigured endpoint that is only discovered when a container dies
// is a Sentinel that has been silently not working for however long.
func New(cfg Config) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		return nil, errors.New("emitter: base URL is required")
	}
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("emitter: base URL must be http or https, got %q", cfg.BaseURL)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	attempts := cfg.MaxAttempts
	if attempts <= 0 {
		attempts = DefaultMaxAttempts
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	client := &Client{
		baseURL:      baseURL,
		incidentsURL: baseURL + IncidentsPath,
		maxAttempts:  attempts,
		timeout:      timeout,
		now:          now,
		events:       cfg.Events,
		version:      cfg.SentinelVersion,
		sleep:        timerSleep,
	}
	if cfg.HTTPClient != nil {
		client.http = cfg.HTTPClient
	} else {
		client.http = &http.Client{Timeout: timeout}
		client.ownsTransport = true
	}
	return client, nil
}

// Close releases the transport's idle connections.
//
// Called from main on shutdown so a rolling update does not leave the process
// waiting on keep-alive connections to the old agent. A no-op for an injected
// client, because a test owns the lifetime of whatever it passed in.
func (c *Client) Close() {
	if c == nil || !c.ownsTransport {
		return
	}
	c.http.CloseIdleConnections()
}

// Outcome classifies what the agent did with a payload.
//
// The three cases are the whole of ROADMAP 3.4.4, and the distinctions matter
// because they imply different responses:
//
//   - Delivered: the agent accepted and triaged the incident. Done.
//   - Rejected: the payload violated the contract. Never retried - the same bytes
//     will fail identically, and retrying a deterministic failure is how a
//     validation bug turns into a self-inflicted denial of service against the
//     agent's job budget.
//   - Escalate: the agent failed internally. Not the Sentinel's bug and not
//     retryable on a short horizon, so the incident is handed to a human. ARCH's
//     fail-closed rule is the same shape: when the automated path cannot be proven
//     to work, escalate rather than proceed.
type Outcome int

const (
	// OutcomeDelivered means the agent accepted the incident.
	OutcomeDelivered Outcome = iota
	// OutcomeRejected means the agent refused the payload as invalid. Fatal.
	OutcomeRejected
	// OutcomeEscalate means the agent failed in a way the Sentinel cannot resolve.
	OutcomeEscalate
)

func (o Outcome) String() string {
	switch o {
	case OutcomeDelivered:
		return "delivered"
	case OutcomeRejected:
		return "rejected"
	case OutcomeEscalate:
		return "escalate"
	default:
		return "unknown"
	}
}

// EmitError is a classified delivery failure.
type EmitError struct {
	// Outcome is the classification, so the caller can branch on it without
	// parsing a message.
	Outcome Outcome
	// StatusCode is the HTTP status, or 0 for a transport-level failure.
	StatusCode int
	// Detail is the agent's response body, truncated. Diagnostic only - it is the
	// agent talking to the Sentinel, not cluster telemetry, so it is not scrubbed.
	//
	// It is also a disclosure channel, because Error() interpolates it and
	// pool.go logs that error verbatim. It is therefore populated ONLY where the
	// body is needed to decide the next action - currently the 429 branch, which
	// reads Retry-After from it. The 2xx branch leaves it empty and reports the
	// diagnosis through Err instead; see verifyVerdict. Adding a field here is a
	// decision about what may reach the log, not a convenience.
	Detail string
	// Attempts is how many POSTs were made.
	Attempts int
	// Err is the underlying cause, if any.
	Err error
}

func (e *EmitError) Error() string {
	status := e.StatusCode
	if status == 0 {
		status = -1
	}
	return fmt.Sprintf("emitter: %s after %d attempt(s), status %d: %v: %s",
		e.Outcome, e.Attempts, status, e.Err, e.Detail)
}

func (e *EmitError) Unwrap() error { return e.Err }

// Classified errors, so a caller can branch without inspecting the Outcome field
// on a possibly-nil pointer.
var (
	// ErrRejected means the agent refused the payload. Fatal: do not retry.
	ErrRejected = errors.New("emitter: payload rejected by the agent")
	// ErrEscalate means the incident must go to a human.
	ErrEscalate = errors.New("emitter: incident requires human escalation")
)

// ErrPayload is a contract violation discovered before the request left.
var ErrPayload = ErrContractViolation

// Dispatch implements [worker.Sink]: it builds the payload from a scrubbed
// incident and emits it.
//
// This is the only path into [Client.Emit] that the pool uses, and it is
// deliberately the only *public* one available to production code - Emit takes a
// payload directly so the round-trip test can hand it a hand-built one.
func (c *Client) Dispatch(ctx context.Context, incident *worker.Incident) error {
	payload, err := Build(incident, BuildOptions{
		SentinelVersion: c.version,
		Now:             c.now,
		Events:          c.events,
	})
	if err != nil {
		// A build failure is the Sentinel's own bug, not the agent's. It is fatal
		// and non-retryable: re-serialising identical input produces the identical
		// error, and the pool is counting this incident as failed either way.
		return &EmitError{Outcome: OutcomeRejected, Attempts: 0, Err: err}
	}
	return c.Emit(ctx, payload)
}

// Emit POSTs a payload to the agent, retrying only what is retryable.
//
// The retry policy is the substance of this function and it is deliberately
// asymmetric:
//
//   - 429 is the agent shedding load (ARCH's bounded job budget, HTTP 429 with
//     {"error": "sandbox_busy"}). It is the one status where retrying is correct,
//     and it is retried with jittered backoff, honouring Retry-After when the
//     agent sends one.
//   - 422 is the contract. Retrying identical bytes is guaranteed to fail again,
//     so the attempt is fatal and the incident is reported as rejected.
//   - 5xx is the agent's own failure. Retrying it would mean the Sentinel holding
//     a worker for a duration it cannot bound, so it is escalated instead.
//   - 4xx other than 422/429 is a routing or authentication error. Also escalated:
//     it will not fix itself, and guessing is not a diagnostic strategy.
func (c *Client) Emit(ctx context.Context, payload *IncidentPayload) error {
	if payload == nil {
		return &EmitError{Outcome: OutcomeRejected, Err: ErrNoIncident}
	}
	if err := Validate(payload); err != nil {
		// Re-validated even though Build already did it, because Emit is public
		// and a caller can hand it anything. Cheap next to a round trip.
		return &EmitError{Outcome: OutcomeRejected, Err: err}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return &EmitError{Outcome: OutcomeRejected, Err: fmt.Errorf("marshal: %w", err)}
	}

	var last *EmitError
	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		// The per-attempt context is derived from the caller's, so a cancellation
		// from the pool's per-incident timeout still propagates and the retry loop
		// cannot outlive its worker.
		attemptCtx, cancel := context.WithTimeout(ctx, c.timeout)
		status, response, err := c.post(attemptCtx, body)
		cancel()
		// `detail` is a bounded excerpt for error messages and Retry-After
		// parsing; `response` is the full bounded body, which is what the 2xx
		// branch has to parse. Truncating to 512 before parsing would reject
		// every real Contract B document.
		detail := truncate(string(response), 512)

		switch {
		case err != nil:
			// A cancelled parent context is terminal, not retryable: the worker is
			// being torn down and there is nothing left to deliver into.
			if ctx.Err() != nil {
				return &EmitError{Outcome: OutcomeEscalate, Attempts: attempt, Err: ctx.Err()}
			}
			last = &EmitError{Outcome: OutcomeEscalate, StatusCode: status, Detail: detail, Attempts: attempt, Err: err}
			if attempt == c.maxAttempts {
				return last
			}
			// A transport failure is retryable, but it must not be retried
			// instantly. Connection-refused against a down agent used to fire the
			// remaining POSTs back-to-back, and the only thing bounding a retry
			// loop against an unreachable host was MaxAttempts - three attempts of
			// "refuse instantly, refuse instantly, escalate" is a busy loop with
			// extra steps, and it collides with every other worker's retry. Back
			// off exactly as the 429 path does: capped full jitter via c.wait,
			// context-aware so it cannot outlive the worker's cancellation.
			if !c.wait(ctx, attempt, detail) {
				return &EmitError{Outcome: OutcomeEscalate, StatusCode: status, Detail: detail, Attempts: attempt, Err: ctx.Err()}
			}

		case status >= 200 && status < 300:
			// A 2xx is a claim about transport, not about triage. The body has
			// to be a Contract B document before "delivered" means anything:
			// a captive portal, an auth proxy and a wrong backend all answer
			// 200, and the earlier version counted every one of them as a
			// delivered verdict with srek3s_sentinel_emitter_failures_total
			// sitting at zero - a monitoring green light over total loss.
			//
			// Detail is DELIBERATELY EMPTY here. EmitError.Error() interpolates
			// it and pool.go logs that error, so carrying the body would put up
			// to 512 bytes of untrusted response into the Sentinel's log on
			// exactly the path where the response is least trustworthy. Detail
			// stays for the paths that need it - Retry-After lives in a body -
			// and verifyVerdict's message carries the diagnosis without the
			// content.
			if err := verifyVerdict(response, payload); err != nil {
				return &EmitError{
					Outcome: OutcomeEscalate, StatusCode: status,
					Attempts: attempt, Err: err,
				}
			}
			return nil

		case status == http.StatusTooManyRequests:
			last = &EmitError{Outcome: OutcomeEscalate, StatusCode: status, Detail: detail, Attempts: attempt, Err: ErrEscalate}
			if attempt == c.maxAttempts {
				return last
			}
			if !c.wait(ctx, attempt, detail) {
				return &EmitError{Outcome: OutcomeEscalate, StatusCode: status, Detail: detail, Attempts: attempt, Err: ctx.Err()}
			}
			continue

		case status == http.StatusUnprocessableEntity:
			// Fatal. No retry, no backoff.
			return &EmitError{Outcome: OutcomeRejected, StatusCode: status, Detail: detail, Attempts: attempt, Err: ErrRejected}

		case status >= 500:
			return &EmitError{Outcome: OutcomeEscalate, StatusCode: status, Detail: detail, Attempts: attempt, Err: ErrEscalate}

		default:
			return &EmitError{Outcome: OutcomeEscalate, StatusCode: status, Detail: detail, Attempts: attempt, Err: ErrEscalate}
		}
	}

	if last == nil {
		last = &EmitError{Outcome: OutcomeEscalate, Err: ErrEscalate}
	}
	return last
}

// post performs one attempt and returns the status and the bounded response body.
//
// The body is capped at MaxResponseBody rather than trusted: a 100 MiB
// text/plain error page from a misrouted request must not become a memory event
// inside the Sentinel.
func (c *Client) post(ctx context.Context, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.incidentsURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() {
		// Drain a bounded amount so the connection can be reused, then close. A
		// fully drained body is what lets keep-alive work; an unread one would
		// force a new TCP connection per incident.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxResponseBody))
		_ = resp.Body.Close()
	}()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBody))
	return resp.StatusCode, payload, nil
}

// verdictEnvelope is the part of Contract B the Sentinel must be able to read.
//
// Deliberately not the whole TriageResponse: the Sentinel has no business
// asserting fields it does not use, and a struct that mirrors all of it would
// turn every additive change to Contract B into a Sentinel change. These are the
// fields whose absence would mean no triage happened.
//
// json.Decoder without DisallowUnknownFields here on purpose - unknown keys in a
// *response* are the agent's business, not a contract violation, and a version
// skew must not fail an otherwise valid verdict.
type verdictEnvelope struct {
	IncidentID       string `json:"incident_id"`
	SchemaVersion    string `json:"schema_version"`
	Status           string `json:"status"`
	BlastRadiusTier  string `json:"blast_radius_tier"`
	AgentVersion     string `json:"agent_version"`
	AnalysisLatencyM int64  `json:"analysis_latency_ms"`
}

// verifyVerdict checks that a 2xx body is a Contract B verdict for *this*
// incident.
//
// What this buys, in the order it was worth discovering:
//
//   - A 2xx from a captive portal, an auth proxy or a wrong backend is not a
//     triage verdict. Before this, every one of them counted as delivered.
//   - The verdict is for this incident. An interceptor that answers 200 with a
//     canned body would otherwise be recorded as a triage of every incident,
//     which is how a stub can make a broken pipeline look healthy.
//   - The tier is one this Sentinel knows. An unrecognised value means the two
//     sides have drifted, and reporting it as delivered hides exactly that.
//
// # Why no value from the body is ever in the returned error
//
// Every field read here came from an untrusted response, and this error is
// logged. The first version of this function interpolated them
// (`blast_radius_tier=%q`, `incident_id=%q`), which is a disclosure channel: a
// party who can answer on the agent's port chooses what the Sentinel's log
// contains. Measured on the pass that found this - a malformed 200 whose body
// carried a planted credential produced 12 verbatim occurrences of it in
// sentinel.log, with the credential arriving through two separate paths.
//
// So the error describes the *shape* of the failure: which field was missing, how
// long the body was, whether it parsed. Lengths and presence are properties of
// the response an operator has to debug; the values are the untrusted part, and
// they do not go in a log line.
//
// Callers must also leave [EmitError.Detail] empty on this path, because
// Error() interpolates Detail. See the 2xx branch in Emit.
func verifyVerdict(body []byte, sent *IncidentPayload) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return fmt.Errorf("%w: the agent returned %d with an empty body, which is not a triage verdict",
			ErrEscalate, http.StatusOK)
	}
	var v verdictEnvelope
	if err := json.Unmarshal(body, &v); err != nil {
		// A json.SyntaxError reports a byte offset, never the input. That is why
		// the parse error can be quoted here while field values cannot.
		return fmt.Errorf("%w: the agent's 2xx body is not JSON (%v) at %d bytes; a 2xx from a proxy or portal is not a triage verdict",
			ErrEscalate, truncate(err.Error(), 120), len(body))
	}
	var missing []string
	if v.IncidentID == "" {
		missing = append(missing, "incident_id")
	}
	if v.Status == "" {
		missing = append(missing, "status")
	}
	if v.BlastRadiusTier == "" {
		missing = append(missing, "blast_radius_tier")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: the agent's 2xx body parsed as JSON but is missing %s (body %d bytes)",
			ErrEscalate, strings.Join(missing, ", "), len(body))
	}
	if sent != nil && v.IncidentID != sent.IncidentID {
		// Only our own id is named. The body's is the untrusted half of a
		// mismatch, and naming it would hand the sender control of this line.
		return fmt.Errorf("%w: the agent's verdict names incident %q, not the one that was sent",
			ErrEscalate, sent.IncidentID)
	}
	switch v.BlastRadiusTier {
	case "TIER_1_TOIL", "TIER_2_ARCHITECTURAL":
	default:
		return fmt.Errorf("%w: the agent returned an unrecognised blast_radius_tier (%d bytes), so the two sides have drifted",
			ErrEscalate, len(v.BlastRadiusTier))
	}
	return nil
}

// wait sleeps for the retry backoff, honouring Retry-After when the agent sent it.
//
// Returns false if the wait was interrupted, so the caller can report the
// cancellation rather than the status. The sleep is on a timer and selects on
// ctx.Done(), never a bare time.Sleep - a bare sleep here would keep a pool worker
// alive past the point its context was cancelled, which is the goroutine leak
// ROADMAP 3.5.4 is written to catch.
func (c *Client) wait(ctx context.Context, attempt int, detail string) bool {
	return c.sleep(ctx, retryDelay(attempt, retryAfter(detail)))
}

// timerSleep is the production sleep: a context-aware pause, never a bare
// time.Sleep - a bare sleep would keep a pool worker alive past the point its
// context was cancelled, which is the goroutine leak ROADMAP 3.5.4 is written to
// catch.
func timerSleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// retryDelay is exponential backoff with full jitter.
//
// Full jitter, not a fixed delay: three pool workers emitting into the same
// agent will be told "busy" at the same moment, and a deterministic backoff would
// have all three return at the same instant and re-collide. Jitter spreads them.
func retryDelay(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}
	// Cap the exponent so a long MaxAttempts cannot overflow the shift.
	exponent := attempt - 1
	if exponent > 6 {
		exponent = 6
	}
	ceiling := baseRetryDelay << exponent
	return time.Duration(rand.Int64N(int64(ceiling) + 1))
}

// retryAfter extracts a Retry-After hint from a response body.
//
// The agent's 429 body is a JSON error envelope, not a bare header, so a header
// parse is not sufficient. Kept deliberately simple: it looks for a
// `retry_after_ms` integer and ignores anything else, because a body that
// contains a number we failed to interpret is not a reason to guess at a delay.
func retryAfter(detail string) time.Duration {
	const key = `"retry_after_ms"`
	index := strings.Index(detail, key)
	if index < 0 {
		return 0
	}
	rest := detail[index+len(key):]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return 0
	}
	rest = rest[colon+1:]
	end := strings.IndexAny(rest, ",}")
	if end < 0 {
		return 0
	}
	milliseconds, err := strconv.Atoi(strings.TrimSpace(rest[:end]))
	if err != nil || milliseconds <= 0 {
		return 0
	}
	return time.Duration(milliseconds) * time.Millisecond
}

// truncate shortens a string to at most n bytes, marking that it was cut.
func truncate(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n] + "... (truncated)"
}
