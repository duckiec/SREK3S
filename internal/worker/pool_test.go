package worker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/srek3s/sentinel/internal/k8s"
)

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

// fakeTelemetry returns canned logs and events, and records what it was asked for.
type fakeTelemetry struct {
	logs   string
	events []corev1.Event

	logErr   error
	eventErr error

	mu       sync.Mutex
	logCalls []logCall
	lastPrev bool
}

type logCall struct {
	namespace, pod, container string
}

func (f *fakeTelemetry) Logs(_ context.Context, namespace, podName, containerName string, previous bool) (string, error) {
	f.mu.Lock()
	f.logCalls = append(f.logCalls, logCall{namespace, podName, containerName})
	f.lastPrev = previous
	f.mu.Unlock()
	if f.logErr != nil {
		return "", f.logErr
	}
	return f.logs, nil
}

func (f *fakeTelemetry) Events(_ context.Context, _, _ string) ([]corev1.Event, error) {
	if f.eventErr != nil {
		return nil, f.eventErr
	}
	return f.events, nil
}

// recordingSink captures dispatched incidents.
type recordingSink struct {
	mu        sync.Mutex
	incidents []*Incident
	err       error
}

func (s *recordingSink) Dispatch(_ context.Context, incident *Incident) error {
	s.mu.Lock()
	s.incidents = append(s.incidents, incident)
	s.mu.Unlock()
	return s.err
}

func (s *recordingSink) all() []*Incident {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Incident, len(s.incidents))
	copy(out, s.incidents)
	return out
}

func eventWithMessage(message string) corev1.Event {
	return corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "evt"},
		Message:    message,
	}
}

func record(name, container string, kind k8s.FailureKind) *k8s.IncidentRecord {
	return &k8s.IncidentRecord{
		DedupKey:      "uid/" + container + ":3",
		Namespace:     "payments",
		PodName:       name,
		PodUID:        "uid-" + name,
		ContainerName: container,
		Kind:          kind,
		ExitCode:      137,
		Restarts:      3,
	}
}

// runPool feeds records through a real channel and blocks until every worker has
// exited.
//
// One helper owns the channel on purpose. An earlier version built the channel in
// the helper and a *different* one inside each test's call to New, so the workers
// read from an empty channel that was never fed and nothing was ever dispatched.
// Every test then failed with "dispatched 0", which reads like a bug in the worker
// rather than a bug in the harness - and the 5s per-test waits made it look like a
// timeout problem instead.
//
// Run returns when the channel is closed and drained, so no test needs to poll.
func runPool(
	records []*k8s.IncidentRecord,
	telemetry TelemetryFetcher,
	sink *recordingSink,
	size int,
) *Pool {
	channel := make(chan *k8s.IncidentRecord, len(records)+1)
	for _, record := range records {
		channel <- record
	}
	close(channel)

	pool := New(channel, telemetry, sink, size)
	pool.Run(context.Background())
	return pool
}

// ---------------------------------------------------------------------------
// Scrubbing: the property the whole package exists for
// ---------------------------------------------------------------------------

// TestRawSecretsAreScrubbedBeforeDispatch is the central guarantee.
//
// A real clientset cannot produce a credential on demand, so the telemetry stub
// plants one. If this regressed, the emitted payload would carry a live secret into
// a GitOps pull request and every clone of the repository.
func TestRawSecretsAreScrubbedBeforeDispatch(t *testing.T) {
	telemetry := &fakeTelemetry{
		logs: strings.Join([]string{
			"level=info msg=\"starting checkout\"",
			"level=error msg=\"alloc failure\" token=abcdef123456 leaked",
			"password: hunter2 in the config dump",
			"AKIAIOSFODNN7EXAMPLE was used here",
		}, "\n"),
		events: []corev1.Event{
			eventWithMessage("OOMKilled with password=hunter2"),
		},
	}
	sink := &recordingSink{}

	runPool([]*k8s.IncidentRecord{record("checkout", "checkout-api", k8s.FailureOOMKilled)}, telemetry, sink, 1)

	dispatched := sink.all()
	if len(dispatched) != 1 {
		t.Fatalf("want 1 dispatched incident, got %d", len(dispatched))
	}
	incident := dispatched[0]

	// Nothing scrubbed may still contain a planted secret.
	for _, line := range incident.ScrubbedLogs {
		for _, secret := range []string{"abcdef123456", "hunter2", "AKIAIOSFODNN7EXAMPLE"} {
			if strings.Contains(line, secret) {
				t.Errorf("log line leaked %q: %s", secret, line)
			}
		}
	}
	for _, message := range incident.ScrubbedEventMessages {
		if strings.Contains(message, "hunter2") {
			t.Errorf("event message leaked the password: %s", message)
		}
	}

	// The redaction report must record that something was masked, without
	// containing it (ARCH §6 M4).
	if incident.Redaction.Total == 0 {
		t.Error("Redaction.Total = 0 despite three planted secrets")
	}
	// RuleID is a named string type, so it has to be converted before it can be
	// joined; fmt is the honest way to say "render these for a leak check".
	rendered := make([]string, 0, len(incident.Redaction.RulesTriggered))
	for _, id := range incident.Redaction.RulesTriggered {
		rendered = append(rendered, string(id))
	}
	serialised := strings.Join(rendered, ",")
	for _, secret := range []string{"abcdef123456", "hunter2", "AKIAIOSFODNN7EXAMPLE"} {
		if strings.Contains(serialised, secret) {
			t.Errorf("the redaction report leaked %q", secret)
		}
	}

	// And the useful content must survive: over-masking everything would also pass
	// the assertions above.
	if !strings.Contains(strings.Join(incident.ScrubbedLogs, "\n"), "alloc failure") {
		t.Error("the diagnostic content was masked along with the secrets")
	}
}

// TestNoScrubbedLineEverContainsABearerToken is a property over several shapes of
// the same leak, since each rule fires on different syntax.
func TestNoScrubbedLineEverContainsABearerToken(t *testing.T) {
	cases := []string{
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdefgh.abcdefgh",
		`{"password":"hunter2","user":"checkout"}`,
		"postgres://payments:hunter2@db.internal:5432/payments",
		"aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
	}
	for _, line := range cases {
		telemetry := &fakeTelemetry{logs: line}
		sink := &recordingSink{}
		runPool([]*k8s.IncidentRecord{record("p", "c", k8s.FailureOOMKilled)}, telemetry, sink, 1)

		dispatched := sink.all()
		if len(dispatched) != 1 {
			t.Fatalf("no dispatch for %q", line)
		}
		got := strings.Join(dispatched[0].ScrubbedLogs, "\n")
		for _, secret := range []string{
			"eyJhbGciOi", "hunter2", "wJalrXUtnFEMI",
		} {
			if strings.Contains(got, secret) {
				t.Errorf("line %q leaked %q after scrubbing: %s", line, secret, got)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Pool mechanics
// ---------------------------------------------------------------------------

func TestPoolProcessesEveryRecord(t *testing.T) {
	telemetry := &fakeTelemetry{logs: "boom"}
	sink := &recordingSink{}
	records := make([]*k8s.IncidentRecord, 0, 20)
	for i := 0; i < 20; i++ {
		records = append(records, record("pod", "c", k8s.FailureOOMKilled))
	}

	pool := runPool(records, telemetry, sink, DefaultPoolSize)

	if got := len(sink.all()); got != 20 {
		t.Errorf("dispatched %d of 20", got)
	}
	if stats := pool.Stats(); stats.Processed != 20 {
		t.Errorf("Stats.Processed = %d, want 20", stats.Processed)
	}
}

// TestPoolRequestsPreviousLogs pins that the worker asks for the previous
// instance, which is the difference between a crash log and a blank one.
func TestPoolRequestsPreviousLogs(t *testing.T) {
	telemetry := &fakeTelemetry{logs: "crash output"}
	sink := &recordingSink{}

	runPool([]*k8s.IncidentRecord{
		record("p", "c", k8s.FailureOOMKilled),
		record("p", "c", k8s.FailureCrashLoopBackOff),
	}, telemetry, sink, 1)

	telemetry.mu.Lock()
	defer telemetry.mu.Unlock()
	if len(telemetry.logCalls) != 2 {
		t.Fatalf("want 2 log fetches, got %d", len(telemetry.logCalls))
	}
	for i := range telemetry.logCalls {
		if !telemetry.lastPrev {
			t.Errorf("log fetch %d did not request the previous instance", i)
		}
	}
}

// TestPoolSizeIsFixed: a pool that grew with the queue would be an unbounded
// queue wearing a disguise (AGENTS.md §3.2).
func TestPoolSizeIsFixed(t *testing.T) {
	if got := New(nil, nil, nil, 0).Size(); got != DefaultPoolSize {
		t.Errorf("size 0 gave %d workers, want the default %d", got, DefaultPoolSize)
	}
	if got := New(nil, nil, nil, -3).Size(); got != DefaultPoolSize {
		t.Errorf("negative size gave %d workers", got)
	}
	if got := New(nil, nil, nil, 5).Size(); got != 5 {
		t.Errorf("Size() = %d, want 5", got)
	}
}

// TestPoolExitsOnContextCancellation is ROADMAP 3.5.2: a channel receive that is
// not select-ed against ctx.Done() keeps a worker alive after shutdown and stops
// the daemon exiting.
func TestPoolExitsOnContextCancellation(t *testing.T) {
	// An open channel that never yields: without a ctx-aware receive this hangs.
	channel := make(chan *k8s.IncidentRecord)
	pool := New(channel, &fakeTelemetry{}, &recordingSink{}, 3)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		pool.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("workers did not exit on cancellation; they are blocked on the channel")
	}
}

// TestPoolExitsWhenChannelCloses covers the watcher's normal shutdown, where the
// egress channel is closed.
func TestPoolExitsWhenChannelCloses(t *testing.T) {
	channel := make(chan *k8s.IncidentRecord, 1)
	channel <- record("p", "c", k8s.FailureOOMKilled)
	close(channel)

	sink := &recordingSink{}
	pool := New(channel, &fakeTelemetry{logs: "x"}, sink, 2)

	done := make(chan struct{})
	go func() {
		defer close(done)
		pool.Run(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("workers did not exit when the channel closed")
	}
	if len(sink.all()) != 1 {
		t.Errorf("dispatched %d, want 1", len(sink.all()))
	}
}

// TestFetchFailureStillDispatches: an apiserver too slow to answer logs must not
// silence the Sentinel. Going quiet is worst when a cluster is unhealthy, which is
// the worst possible correlation between cause and effect.
func TestFetchFailureStillDispatches(t *testing.T) {
	telemetry := &fakeTelemetry{
		logErr:   errors.New("apiserver timeout"),
		eventErr: errors.New("apiserver timeout"),
	}
	sink := &recordingSink{}

	runPool([]*k8s.IncidentRecord{record("p", "c", k8s.FailureOOMKilled)}, telemetry, sink, 1)

	dispatched := sink.all()
	if len(dispatched) != 1 {
		t.Fatalf("a telemetry failure suppressed the incident entirely; want it dispatched with the gap recorded")
	}
	if dispatched[0].LogsFetched {
		t.Error("LogsFetched = true despite a fetch failure")
	}
	if len(dispatched[0].ScrubbedLogs) != 0 {
		t.Errorf("unscrubbed log content present: %v", dispatched[0].ScrubbedLogs)
	}
}

func TestDispatchFailureIsCountedNotPanicked(t *testing.T) {
	sink := &recordingSink{err: errors.New("agent unreachable")}

	channel := make(chan *k8s.IncidentRecord, 1)
	channel <- record("p", "c", k8s.FailureOOMKilled)
	close(channel)
	pool := New(channel, &fakeTelemetry{logs: "x"}, sink, 1)
	pool.Run(context.Background())

	if stats := pool.Stats(); stats.Failed != 1 {
		t.Errorf("Stats.Failed = %d, want 1", stats.Failed)
	}
	if stats := pool.Stats(); stats.Processed != 0 {
		t.Errorf("Stats.Processed = %d on a failed dispatch, want 0", stats.Processed)
	}
}

// TestUnquotedAWSSecretKeyIsScrubbed is the regression for a P0 credential leak.
//
// An unquoted AWS secret access key used to pass the whole 11-rule pipeline
// unmasked: rule 3 is anchored on quotes around the 40-character value, and rule
// 7's key alternation contained `secret[_-]?key`, which does not occur inside
// `secret_access_key`, so neither rule could match it. An env dump or a
// `key=value` log line carries exactly that shape.
//
// Fixed by ARCH §6.6, which gave rule 7 an optional access segment. This test
// previously documented the gap instead of asserting the fix, and inverted its own
// assertion while doing so - it errored precisely because the secret survived,
// which made a correct-behaviour run look like flakiness.
func TestUnquotedAWSSecretKeyIsScrubbed(t *testing.T) {
	// Unquoted forms are rule 7's job, and rule 7 is group-preserving: it keeps
	// the key name and the separator and replaces only the value.
	unquoted := []string{
		"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"aws-secret-access-key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	for _, line := range unquoted {
		telemetry := &fakeTelemetry{logs: line}
		sink := &recordingSink{}
		runPool([]*k8s.IncidentRecord{record("p", "c", k8s.FailureOOMKilled)}, telemetry, sink, 1)

		dispatched := sink.all()
		if len(dispatched) != 1 {
			t.Fatalf("no dispatch for %q", line)
		}
		got := strings.Join(dispatched[0].ScrubbedLogs, "\n")
		if strings.Contains(got, "wJalrXUtnFEMI") {
			t.Errorf("unquoted AWS secret key leaked after ARCH 6.6: %s", got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("no redaction marker for %q: %s", line, got)
		}
		// The key name must survive. The value is the secret; the name is the
		// diagnostic. A mask that destroyed both would satisfy the two assertions
		// above while telling an operator nothing about what leaked.
		//
		// Compared case-insensitively, because the rule is `(?i)` and an uppercase
		// key is masked just as thoroughly. An earlier version compared
		// case-sensitively and failed on AWS_SECRET_ACCESS_KEY.
		lower := strings.ToLower(got)
		if !strings.Contains(lower, "secret_access_key") &&
			!strings.Contains(lower, "secret-access-key") {
			t.Errorf("the key name was destroyed along with the value: %s", got)
		}
	}

	// The quoted form is rule 3's job, and rule 3 replaces the whole matched span,
	// so the key name is intentionally *not* preserved. Asserted separately so the
	// distinction is recorded rather than papered over - the earlier version
	// asserted key-name survival for this case too and failed on correct
	// behaviour, which is how a case-sensitive bug here went unnoticed.
	quoted := `aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
	telemetry := &fakeTelemetry{logs: quoted}
	sink := &recordingSink{}
	runPool([]*k8s.IncidentRecord{record("p", "c", k8s.FailureOOMKilled)}, telemetry, sink, 1)
	got := strings.Join(sink.all()[0].ScrubbedLogs, "\n")
	if strings.Contains(got, "wJalrXUtnFEMI") {
		t.Errorf("the quoted form leaked: %s", got)
	}
}

// TestSplitLines handles the blob-to-slice boundary correctly.
func TestSplitLines(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"one", 1},
		{"one\ntwo", 2},
		{"one\ntwo\n", 2},
		{"\n", 0},
		{"a\n\nb", 3},
	}
	for _, tc := range cases {
		if got := len(splitLines(tc.in)); got != tc.want {
			t.Errorf("splitLines(%q) gave %d lines, want %d", tc.in, got, tc.want)
		}
	}
}

// TestConcurrentWorkersDoNotInterleaveTelemetry keeps the per-incident state in
// one struct rather than in shared scratch, so three workers cannot bleed one
// incident's logs into another's.
func TestConcurrentWorkersDoNotInterleaveTelemetry(t *testing.T) {
	records := make([]*k8s.IncidentRecord, 0, 30)
	for i := 0; i < 30; i++ {
		records = append(records, record("pod", "container-a", k8s.FailureOOMKilled))
	}
	// Each record identifies itself in the log it should receive.
	telemetry := &identityTelemetry{}
	sink := &recordingSink{}
	runPool(records, telemetry, sink, DefaultPoolSize)

	for _, incident := range sink.all() {
		want := incident.Record.PodName
		got := strings.Join(incident.ScrubbedLogs, "\n")
		if !strings.Contains(got, want) {
			t.Errorf("incident for %q received logs containing %q; state bled between workers", want, got)
		}
	}
}

// identityTelemetry echoes the pod name into the log so cross-talk is detectable.
type identityTelemetry struct{}

func (identityTelemetry) Logs(
	_ context.Context, _, podName, _ string, _ bool,
) (string, error) {
	return "log for " + podName, nil
}

func (identityTelemetry) Events(
	_ context.Context, _, _ string,
) ([]corev1.Event, error) {
	return nil, nil
}
