// Package worker consumes incident records from the watcher and prepares them
// for emission.
//
// The pool exists because the watcher's egress channel is non-blocking by design:
// it drops rather than stalls. That is correct - a blocked informer callback
// freezes observation of *every* pod in the cluster - but it means someone has to
// drain the channel, and a single consumer would serialise all telemetry fetches
// behind one slow apiserver call.
//
// Fixed size, not dynamic: AGENTS.md §3.2 forbids unbounded goroutines, and a pool
// that grows with the queue is just an unbounded queue wearing a disguise.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/srek3s/sentinel/internal/k8s"
	"github.com/srek3s/sentinel/internal/metrics"
	"github.com/srek3s/sentinel/internal/scrubber"
)

// DefaultPoolSize is the fixed worker count.
//
// Three: enough to overlap a slow log fetch against a fast one without letting a
// burst of incidents spawn an unbounded number of in-flight apiserver requests.
// Every worker holds one TelemetryTimeout x 2 (logs + events) worst case, so this
// bounds concurrent API load at a predictable six requests.
const DefaultPoolSize = 3

// ErrPoolDrained is returned by Sink implementations that have nothing to do.
var ErrPoolDrained = errors.New("worker: incident not dispatched")

// TelemetryFetcher is the evidence source a worker needs.
//
// An interface rather than *k8s.Telemetry so tests can substitute a fetcher that
// returns a planted secret and assert the scrubber removed it - which is the
// property that matters, and which a real clientset cannot produce on demand.
type TelemetryFetcher interface {
	Logs(ctx context.Context, namespace, podName, containerName string, previous bool) (string, error)
	Events(ctx context.Context, namespace, podUID string) ([]corev1.Event, error)
}

// Sink receives a scrubbed incident.
//
// Mocked at ROADMAP §3.4's boundary for now: the HTTP client is the next task and
// the interface is what it will implement, so nothing above this line changes when
// it lands.
type Sink interface {
	Dispatch(ctx context.Context, incident *Incident) error
}

// Incident is one work item, telemetry fetched and scrubbed.
type Incident struct {
	// Identity, copied from the record. Never scrubbed: these are identifiers.
	Record    *k8s.IncidentRecord
	Namespace string
	PodName   string
	PodUID    string
	Container string
	Kind      string
	ExitCode  int32
	Restarts  int32

	// PreviousReason is the prior instance's termination reason, "" when the
	// container has never restarted. Passed through rather than re-read: the
	// kubelet overwrites it once the container comes back, so by dispatch time it
	// is gone from the API.
	PreviousReason string

	// Resources is the container's declared limits and requests as they were when
	// the failure was observed. See IncidentRecord.Resources for why they are
	// captured at classification rather than fetched at dispatch.
	Resources k8s.ContainerResources

	// ScrubbedLogs is the evidence, scrubbed in memory. Nothing unscrubbed leaves
	// this struct, which is what makes "no raw secret can reach the request body"
	// checkable rather than aspirational.
	ScrubbedLogs []string

	// ScrubbedEventMessages is the same for event messages.
	ScrubbedEventMessages []string

	// Redaction is the scrubber's accounting: counts and rule IDs only, never the
	// masked values (ARCH §6 M4).
	Redaction scrubber.RedactionReport

	// EventsFetched and LogsFetched report what could be collected. An incident
	// whose logs could not be fetched is still dispatched - with the gap recorded -
	// because an RCA with no logs beats no RCA at all.
	EventsFetched int
	LogsFetched   bool
}

// Stats is a snapshot of pool counters.
type Stats struct {
	Processed uint64
	Failed    uint64
	// Dropped counts records this pool refused: a full channel at send time, and
	// queued work still unclaimed when a shutdown signal arrived. It was a field
	// that always read zero before, which is the same failure shape as a
	// ShutdownGrace that was never waited on - a number an operator reasonably
	// assumes is measuring something.
	Dropped  uint64
	InFlight int64
}

// Pool is a fixed set of workers draining the watcher's channel.
type Pool struct {
	size      int
	records   <-chan *k8s.IncidentRecord
	telemetry TelemetryFetcher
	sink      Sink
	log       *slog.Logger
	metrics   *metrics.Registry

	// perIncidentTimeout bounds the whole telemetry phase for one incident, so one
	// slow apiserver cannot consume the pool indefinitely. Individual calls are
	// bounded tighter inside Telemetry.
	perIncidentTimeout time.Duration

	wg sync.WaitGroup

	processed atomic.Uint64
	failed    atomic.Uint64
	dropped   atomic.Uint64
	inFlight  atomic.Int64
}

// Option configures a Pool.
type Option func(*Pool)

// WithLogger sets the logger.
func WithLogger(log *slog.Logger) Option {
	return func(p *Pool) { p.log = log }
}

// WithPerIncidentTimeout bounds the telemetry phase of one incident.
func WithPerIncidentTimeout(d time.Duration) Option {
	return func(p *Pool) { p.perIncidentTimeout = d }
}

// WithMetrics attaches the Prometheus registry. A nil registry is a no-op,
// so tests and embeddings that do not care about metrics pass nothing.
func WithMetrics(m *metrics.Registry) Option {
	return func(p *Pool) { p.metrics = m }
}

// New builds a pool over the given channel.
//
// size <= 0 falls back to DefaultPoolSize rather than starting zero workers,
// which would silently drain nothing while looking healthy.
func New(
	records <-chan *k8s.IncidentRecord,
	telemetry TelemetryFetcher,
	sink Sink,
	size int,
	opts ...Option,
) *Pool {
	if size <= 0 {
		size = DefaultPoolSize
	}
	p := &Pool{
		size:               size,
		records:            records,
		telemetry:          telemetry,
		sink:               sink,
		log:                slog.Default(),
		perIncidentTimeout: 2 * k8s.TelemetryTimeout,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Start launches the fixed worker set.
//
// Returns immediately; Run blocks until the workers finish. ctx is honoured, so a
// SIGTERM-driven shutdown stops workers taking new work rather than only finishing
// what they already have - which is what ROADMAP 3.3.5 asks for.
func (p *Pool) Start(ctx context.Context) {
	p.wg.Add(p.size)
	for i := 0; i < p.size; i++ {
		go func(id int) {
			defer p.wg.Done()
			p.loop(ctx, id)
		}(i)
	}
}

// Run starts the pool and blocks until every worker has exited.
func (p *Pool) Run(ctx context.Context) {
	p.Start(ctx)
	p.wg.Wait()
}

// Wait blocks until every started worker has exited.
//
// Split out from [Pool.Run] so a caller that needs to do something *while* the
// pool drains - bound the wait, report what was in flight, log a final snapshot -
// can do it without a second pool. ROADMAP 3.3.5 is the reason: a SIGTERM handler
// that calls Run and then exits has no point at which it can observe whether the
// drain completed.
//
// Safe to call on a pool that was never started: the WaitGroup counter is zero, so
// Wait returns immediately. That is what makes it usable from a defer or a test.
func (p *Pool) Wait() {
	p.wg.Wait()
}

// loop is one worker's read/dispatch cycle.
//
// The channel receive is select-ed against ctx.Done(): an unconditional receive
// would keep a worker alive after shutdown and prevent the daemon from exiting,
// which is the goroutine leak ROADMAP 3.5.4 tests for.
//
// The run context is honoured here and only here. That is what makes it the right
// seam: cancelling it stops workers taking new work, while work already inside
// handle is protected by handle itself. See handle for why the incident context
// cannot descend from this one.
func (p *Pool) loop(ctx context.Context, id int) {
	for {
		// Checked BEFORE the select, not after it. A select with two ready arms
		// picks between them at random, so a worker that finished an incident into
		// a non-empty queue would take one more about half the time - and that one
		// extra would be protected by handle's stripped context, so the shutdown
		// grace would silently become however long the backlog took. Checking first
		// is what makes "stops taking new work at the signal" a fact rather than a
		// coin toss.
		if ctx.Err() != nil {
			p.refuseBuffered(id)
			p.log.Info("worker stopping", "worker", id, "reason", ctx.Err())
			return
		}
		select {
		case <-ctx.Done():
			// Reachable only when the worker was parked on the channel when the
			// signal arrived. The buffer is empty by construction here, but
			// refuseBuffered runs anyway: it is the same decision, and a future
			// change to what "parked" means should not silently change whether the
			// refusal is accounted.
			p.refuseBuffered(id)
			p.log.Info("worker stopping", "worker", id, "reason", ctx.Err())
			return
		case record, ok := <-p.records:
			if !ok {
				p.log.Info("worker exiting: channel closed", "worker", id)
				return
			}
			if record == nil {
				continue
			}
			p.handle(ctx, record)
		}
	}
}

// refuseBuffered counts and discards whatever is already in the channel, then
// returns. It never blocks: records not yet sent are not this pool's to refuse,
// and draining past the buffer would deadlock a worker on a live channel.
//
// Counting them matters. A container failure dropped at shutdown leaves no trace
// anywhere - not in the incident log, not in a counter, not in an event. Before
// this existed the same shape was possible in two places at once (the select
// coin toss, and a closed channel hiding a non-empty buffer) and neither left a
// number. "Refused at shutdown" is the one outcome of a drain an operator cannot
// infer from anything else, so it is recorded rather than allowed to pass as a
// normal exit.
func (p *Pool) refuseBuffered(id int) {
	for {
		select {
		case record, ok := <-p.records:
			if !ok {
				// Closed and drained. Every worker is leaving and nothing else
				// will read what was in here, so the buffer is genuinely gone.
				p.log.Info("channel closed with work unclaimed at shutdown",
					"worker", id,
					"refused_total", p.dropped.Load(),
				)
				return
			}
			if record == nil {
				continue
			}
			p.dropped.Add(1)
			p.log.Info("refusing queued work after shutdown",
				"worker", id,
				"incident", record.Namespace+"/"+record.PodName+":"+record.ContainerName,
				"refused_total", p.dropped.Load(),
			)
		default:
			return
		}
	}
}

// handle fetches, scrubs and dispatches one incident.
// handle fetches, scrubs and dispatches one incident.
//
// # Why the run context is stripped before the deadline is applied
//
// The incident's context must NOT descend from the run context. It used to, and
// that made [cmd/sentinel.ShutdownGrace] decorative: SIGTERM cancels the run
// context, the cancellation propagated into every in-flight incident, and each
// aborted mid-flight on the next apiserver call. Measured on the pass that found
// it - a pool with seven queued incidents exited 56ms after the signal against a
// 20s grace, reporting processed:0, failed:7. Seven incidents classified,
// scrubbed and emitted into a log nobody will read, then gone. The drain main
// waits for had nothing left to wait on.
//
// context.WithoutCancel keeps the values (trace and deadline metadata, if any are
// ever attached) and drops the cancellation. The bound that replaces it is not
// weaker, it is different in kind:
//
//   - [Pool.perIncidentTimeout] still caps one incident absolutely. A hung
//     apiserver or a hung agent still ends at 135s.
//   - [Pool.loop] still stops workers *taking* new work the moment the signal
//     arrives. Only work already started is protected.
//
// So "graceful" means: work already begun gets to finish, up to its own budget.
// New work is refused immediately. That is the ordinary meaning, and the one
// main.go's comment has always claimed.
//
// The residual is real and is not papered over: an incident needing more than
// ShutdownGrace still loses, because Kubernetes SIGKILLs at
// terminationGracePeriodSeconds. When that happens main logs an error and exits
// non-zero, which is the signal an operator needs. Widening ShutdownGrace past the
// per-incident timeout would mean an incident can never be lost to a drain, but it
// would also mean the pod's own grace period has to exceed the incident budget -
// a deployment decision, recorded as such.
func (p *Pool) handle(parent context.Context, record *k8s.IncidentRecord) {
	p.inFlight.Add(1)
	defer p.inFlight.Add(-1)

	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), p.perIncidentTimeout)
	defer cancel()

	incident := &Incident{
		Record:    record,
		Namespace: record.Namespace,
		PodName:   record.PodName,
		PodUID:    record.PodUID,
		Container: record.ContainerName,
		Kind:      string(record.Kind),
		ExitCode:  record.ExitCode,
		Restarts:  record.Restarts,

		PreviousReason: record.PreviousReason,
		Resources:      record.Resources,
	}

	p.collectTelemetry(ctx, incident)
	p.scrubTelemetry(ctx, incident)

	p.metrics.IncIntercepted()
	if err := p.sink.Dispatch(ctx, incident); err != nil {
		p.failed.Add(1)
		p.metrics.IncEmitterFailure()
		p.log.Error("dispatch failed",
			"incident", record.Namespace+"/"+record.PodName+":"+record.ContainerName,
			"kind", string(record.Kind),
			"error", err,
		)
		return
	}
	p.processed.Add(1)
}

// collectTelemetry fetches logs and events, recording gaps rather than failing.
//
// A fetch error is logged and the incident continues. The alternative - abandon the
// incident when the apiserver is slow - means the Sentinel goes silent exactly when
// a cluster is unhealthy, which is the worst possible correlation between cause and
// effect.
func (p *Pool) collectTelemetry(ctx context.Context, incident *Incident) {
	if p.telemetry == nil {
		return
	}

	logs, err := p.telemetry.Logs(
		ctx,
		incident.Namespace,
		incident.PodName,
		incident.Container,
		k8s.PreviousLogsFor(k8s.FailureKind(incident.Kind)),
	)
	if err != nil {
		p.log.Warn("log fetch failed; dispatching without logs",
			"namespace", incident.Namespace,
			"pod", incident.PodName,
			"container", incident.Container,
			"error", err,
		)
	} else if logs != "" {
		incident.LogsFetched = true
		incident.ScrubbedLogs = splitLines(logs)
	}

	events, err := p.telemetry.Events(ctx, incident.Namespace, incident.PodUID)
	if err != nil {
		p.log.Warn("event fetch failed; dispatching without events",
			"namespace", incident.Namespace,
			"pod", incident.PodName,
			"error", err,
		)
		return
	}
	incident.EventsFetched = len(events)

	messages := make([]string, 0, len(events))
	for i := range events {
		if message := events[i].Message; message != "" {
			messages = append(messages, message)
		}
	}
	incident.ScrubbedEventMessages = messages
}

// scrubTelemetry runs every fetched string through the in-memory scrubber.
//
// The single point where raw telemetry becomes safe. Nothing above this function
// ever holds unscrubbed text, which is what makes ROADMAP 3.4.5's "no raw secret
// can reach the request body" a property of the type rather than a code review.
func (p *Pool) scrubTelemetry(ctx context.Context, incident *Incident) {
	if len(incident.ScrubbedLogs) == 0 && len(incident.ScrubbedEventMessages) == 0 {
		return
	}

	// Scrubbed in memory, before serialisation, and never logged (AGENTS.md §1).
	lines, report := scrubber.ScrubLines(ctx, incident.ScrubbedLogs)
	incident.ScrubbedLogs = lines

	messages, messageReport := scrubber.ScrubLines(ctx, incident.ScrubbedEventMessages)
	incident.ScrubbedEventMessages = messages

	incident.Redaction = mergeReports(report, messageReport)
	for _, id := range incident.Redaction.RulesTriggered {
		p.metrics.IncMasked(string(id))
	}
}

// mergeReports combines two scrubber reports without double-counting.
//
// The second report's Total is not added, because both passes scrubbed *different*
// strings and the totals are already disjoint. Adding it would overstate the
// redaction count for an incident with both logs and events.
func mergeReports(logs, events scrubber.RedactionReport) scrubber.RedactionReport {
	merged := scrubber.RedactionReport{Total: logs.Total}
	seen := map[scrubber.RuleID]bool{}
	for _, id := range logs.RulesTriggered {
		seen[id] = true
		merged.RulesTriggered = append(merged.RulesTriggered, id)
	}
	for _, id := range events.RulesTriggered {
		if !seen[id] {
			seen[id] = true
			merged.RulesTriggered = append(merged.RulesTriggered, id)
		}
	}
	return merged
}

// splitLines turns a log blob into the line slice the scrubber expects.
//
// Empty trailing content is dropped so a log ending in "\n" does not produce a
// final empty entry that the scrubber would then report on.
func splitLines(blob string) []string {
	if blob == "" {
		return nil
	}
	trimmed := blob
	if len(trimmed) > 0 && trimmed[len(trimmed)-1] == '\n' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

// Stats returns a point-in-time snapshot.
// PerIncidentTimeout reports the deadline this pool imposes on one incident's
// telemetry-and-dispatch phase.
//
// Exposed because the deadline is chosen by the caller, not by the pool: the
// worker's default (2 * k8s.TelemetryTimeout) is sized for telemetry, and a caller
// whose sink talks to something slow must raise it. Without an accessor the only
// way to observe the value is a timing test, which is how this went unnoticed -
// cmd/sentinel's emitter budget was unreachable while every timeout constant in
// the tree agreed with every other.
func (p *Pool) PerIncidentTimeout() time.Duration { return p.perIncidentTimeout }

func (p *Pool) Stats() Stats {
	return Stats{
		Processed: p.processed.Load(),
		Failed:    p.failed.Load(),
		Dropped:   p.dropped.Load(),
		InFlight:  p.inFlight.Load(),
	}
}

// Size reports the fixed worker count.
func (p *Pool) Size() int { return p.size }
