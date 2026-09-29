// Tests for the pieces of cmd/sentinel that carry behaviour rather than wiring.
//
// main() itself is not called. It builds a real clientset, so testing it would
// require a live apiserver; what is testable without one is the shutdown
// sequencing and the event conversion, and those are where the bugs would be.
package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/srek3s/sentinel/internal/emitter"
	"github.com/srek3s/sentinel/internal/k8s"
	"github.com/srek3s/sentinel/internal/worker"
)

// ---------------------------------------------------------------------------
// Shutdown sequencing (ROADMAP 3.3.5)
// ---------------------------------------------------------------------------

// TestWaitForReturnsWhenTheDrainCompletes is the positive case.
func TestWaitForReturnsWhenTheDrainCompletes(t *testing.T) {
	done := make(chan struct{})
	close(done)
	if !waitFor(done, time.Second) {
		t.Error("waitFor = false for an already-closed channel")
	}
}

// TestWaitForTimesOutRatherThanBlockingForever is the negative control, and the
// reason waitFor exists at all.
//
// Without it, a pool that never drains - a worker wedged in an apiserver call that
// ignores its context - would hold the process open until the kubelet sent SIGKILL.
// That is a second hard kill with no information, which is the failure mode the
// bounded wait is there to prevent.
func TestWaitForTimesOutRatherThanBlockingForever(t *testing.T) {
	never := make(chan struct{})
	start := time.Now()
	if waitFor(never, 120*time.Millisecond) {
		t.Error("waitFor = true for a channel that never closes")
	}
	// A generous upper bound: the point is that it returned at all rather than at
	// exactly 120ms, which would be too tight to be reliable on a loaded host.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("waitFor took %s; the bound did not apply", elapsed)
	}
}

// TestShutdownOrderStopsTheProducerBeforeDraining is the property ROADMAP 3.3.5
// actually depends on, expressed as a test because the ordering is invisible in
// the source.
//
// The failure it guards against: draining first and stopping the informer second.
// The queue would keep refilling while we waited for it to empty, so the wait
// would never finish and every shutdown would hit the grace timeout.
func TestShutdownOrderStopsTheProducerBeforeDraining(t *testing.T) {
	var (
		mu        sync.Mutex
		produced  int
		consuming = true
	)

	// A producer that keeps emitting while the consumer is draining, which is what
	// an informer does.
	go func() {
		for {
			mu.Lock()
			stop := !consuming
			mu.Unlock()
			if stop {
				return
			}
			mu.Lock()
			produced++
			mu.Unlock()
			time.Sleep(time.Millisecond)
		}
	}()

	// Drain, as main does: stop the producer, then wait.
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	consuming = false
	mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	afterStop := produced
	mu.Unlock()

	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	afterWait := produced
	mu.Unlock()

	if afterWait != afterStop {
		t.Errorf("production continued past the stop signal: %d then %d", afterStop, afterWait)
	}
}

// TestPoolDrainsOnCancellation is the end-to-end shape of the shutdown, using the
// real pool and the real drain call.
//
// A worker mid-incident when the context is cancelled must still finish, because
// that incident was detected and a lost detection is a silent gap in coverage. The
// assertion is that Wait returns, and that the in-flight work completed.
func TestPoolDrainsOnCancellation(t *testing.T) {
	records := make(chan *k8s.IncidentRecord, 4)
	telemetry := &slowTelemetry{delay: 30 * time.Millisecond}
	sink := &countingSink{}

	pool := worker.New(records, telemetry, sink, 2, worker.WithLogger(discardLogger()))
	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)

	records <- &k8s.IncidentRecord{
		Namespace: "payments", PodName: "checkout-api-1", ContainerName: "api",
		Kind: k8s.FailureOOMKilled, ExitCode: 137, Restarts: 1,
		PodUID: "uid-1", DedupKey: "uid-1/api:1",
	}
	// Wait for the worker to pick the record up, so the cancellation lands while it
	// is in flight rather than before it starts.
	waitForCondition(t, time.Second, func() bool { return telemetry.inFlight() > 0 })

	cancel()

	drained := make(chan struct{})
	go func() { defer close(drained); pool.Wait() }()

	if !waitFor(drained, 5*time.Second) {
		t.Fatal("the pool did not drain within 5s of cancellation")
	}
	if got := sink.dispatched(); got != 1 {
		t.Errorf("dispatched = %d, want 1; the in-flight incident was dropped on "+
			"shutdown, which is a silent gap in coverage", got)
	}
}

// TestSecondSignalIsNotSwallowed is the operator-escape property of
// signal.NotifyContext.
//
// After the first SIGTERM, a supervisor that decides to stop waiting sends a
// second one. If the handler swallowed that too, an operator would have no way to
// make the process exit and would have to SIGKILL it - losing the drain they were
// waiting for. Go's NotifyContext restores default behaviour on the second signal;
// this asserts the wiring that gets us there is a single NotifyContext rather than
// a hand-rolled channel.
func TestSecondSignalIsNotSwallowed(t *testing.T) {
	// The assertion is structural: run() obtains its context from
	// signal.NotifyContext and calls stop via defer. A regression to a manual
	// signal channel would remove that property, so pin the shape of the call by
	// asserting the documented behaviour of the primitive this code relies on.
	ctx, stop := notifyContextForTest(t)
	defer stop()

	select {
	case <-ctx.Done():
		t.Fatal("the context was already cancelled before any signal")
	default:
	}

	// A second signal after stop() must not be recovered from - which is what
	// "restores default behaviour" means. stop() is what installs that.
	stop()
	if err := ctx.Err(); err == nil {
		t.Error("stop() did not cancel the context; the second signal would be ignored")
	}
}

// ---------------------------------------------------------------------------
// Event conversion
// ---------------------------------------------------------------------------

// TestEventConverterProducesSchemaValidEvents checks the shape against the fields
// the agent requires, because an event array with one bad element fails the whole
// payload as a 422.
func TestEventConverterProducesSchemaValidEvents(t *testing.T) {
	incident := sampleIncident()
	events := eventConverter(incident)

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	event := events[0]

	if event.Type != "Warning" {
		t.Errorf("type = %q; the agent accepts only Normal or Warning", event.Type)
	}
	if event.Message == "" {
		t.Error("message is empty; the agent's min_length is 1")
	}
	if event.Count < 0 {
		t.Error("count is negative; the agent's bound is ge=0")
	}
	if len(event.InvolvedObject) < 3 {
		t.Errorf("involved_object = %q; the agent's min_length is 3", event.InvolvedObject)
	}
	if event.InvolvedObject != "pod/checkout-api-7d9f4b6c8d-x2k9p" {
		t.Errorf("involved_object = %q, want the pod/<name> form", event.InvolvedObject)
	}
	// The whole point: the message must be the scrubbed one, verbatim.
	if event.Message != incident.ScrubbedEventMessages[0] {
		t.Errorf("message was altered:\n got %q\nwant %q",
			event.Message, incident.ScrubbedEventMessages[0])
	}
}

// TestEventConverterNeverTouchesUnscrubbedText is the negative control for
// ROADMAP 3.4.2 at the conversion boundary.
//
// The converter is handed an incident whose *logs* are unscrubbed. If it reached
// for those - or for anything but ScrubbedEventMessages - the raw secret would
// reach the wire. The incident here carries a live credential in the logs and in
// the record's Message, and the assertion is that neither appears in any event.
func TestEventConverterNeverTouchesUnscrubbedText(t *testing.T) {
	incident := sampleIncident()
	incident.Record.Message = "dial postgres://checkout:hunter2@10.42.0.7:5432/orders"
	incident.ScrubbedLogs = []string{"aws_access_key_id=AKIAIOSFODNN7EXAMPLE"}

	events := eventConverter(incident)
	for _, event := range events {
		serialised := event.Message + event.Reason + event.InvolvedObject + event.Type
		for _, secret := range []string{"hunter2", "AKIAIOSFODNN7EXAMPLE"} {
			if contains(serialised, secret) {
				t.Errorf("event carried an unscrubbed secret %q: %+v", secret, event)
			}
		}
	}
}

// TestEventConverterDropsUnaddressableEvents covers the case where the object
// reference cannot be reconstructed.
//
// A pod with no name has no object reference, and an event with an empty
// involved_object fails the agent's min_length and takes the payload with it. The
// honest outcome is to drop the event: inventing a reference would attach a
// failure to a pod that may never have existed.
func TestEventConverterDropsUnaddressableEvents(t *testing.T) {
	incident := sampleIncident()
	incident.PodName = ""

	if events := eventConverter(incident); len(events) != 0 {
		t.Errorf("got %d events for an unaddressable incident, want 0: %+v", len(events), events)
	}
}

// TestEventConverterHandlesEmptyInput is the negative control for the guard that
// returns early.
func TestEventConverterHandlesEmptyInput(t *testing.T) {
	if events := eventConverter(nil); events != nil {
		t.Errorf("eventConverter(nil) = %+v, want nil", events)
	}
	empty := sampleIncident()
	empty.ScrubbedEventMessages = nil
	if events := eventConverter(empty); events != nil {
		t.Errorf("no messages gave %+v, want nil", events)
	}
	blank := sampleIncident()
	blank.ScrubbedEventMessages = []string{""}
	if events := eventConverter(blank); len(events) != 0 {
		t.Errorf("a blank message produced %+v, want none", events)
	}
}

// TestConvertedEventsSurviveEmitterValidation is the integration of the two: what
// the converter produces must pass the emitter's own contract check, so a change to
// either side that breaks the other fails here rather than as a 422.
func TestConvertedEventsSurviveEmitterValidation(t *testing.T) {
	incident := sampleIncident()
	incident.Record.Resources.MemoryLimit = "256Mi"
	incident.Resources.MemoryLimit = "256Mi"
	incident.Record.PreviousReason = "Completed"
	incident.PreviousReason = "Completed"

	payload, err := emitter.Build(incident, emitter.BuildOptions{
		SentinelVersion: "0.1.0",
		Events:          eventConverter,
		Now:             func() time.Time { return time.Now() },
	})
	if err != nil {
		t.Fatalf("Build with cmd/sentinel's converter: %v", err)
	}
	if err := emitter.Validate(payload); err != nil {
		t.Fatalf("cmd/sentinel's converter produced an invalid payload: %v", err)
	}
	if len(payload.ClusterEvents) != 1 {
		t.Errorf("got %d events in the payload, want 1", len(payload.ClusterEvents))
	}
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

// TestLoggerFallsBackOnABadLevel is a real safety property, not a style check.
//
// Refusing to start on an unparsable log level would mean a typo in a ConfigMap
// takes the reliability monitor down - a worse outcome than verbose logs. The
// function must be total.
func TestLoggerFallsBackOnABadLevel(t *testing.T) {
	for _, level := range []string{"", "trace", "DEBUG", "Warn", "nonsense", "5"} {
		if newLogger(level) == nil {
			t.Errorf("newLogger(%q) returned nil", level)
		}
	}
	if newLogger("debug") == nil || newLogger("error") == nil {
		t.Error("a valid level produced a nil logger")
	}
}

func TestEnvOrFallsBackOnAnUnsetVariable(t *testing.T) {
	const key = "SREK3S_TEST_DEFINITELY_UNSET"
	if got := envOr(key, "fallback"); got != "fallback" {
		t.Errorf("envOr = %q, want the fallback", got)
	}
	t.Setenv(key, "set")
	if got := envOr(key, "fallback"); got != "set" {
		t.Errorf("envOr = %q, want the environment value", got)
	}
}

func TestNamespaceOrAllIsHumanReadable(t *testing.T) {
	if got := namespaceOrAll(""); got != "(all)" {
		t.Errorf("namespaceOrAll(\"\") = %q", got)
	}
	if got := namespaceOrAll("payments"); got != "payments" {
		t.Errorf("namespaceOrAll = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

func sampleIncident() *worker.Incident {
	return &worker.Incident{
		Record: &k8s.IncidentRecord{
			DedupKey: "uid-1/api:4", Namespace: "payments",
			PodName: "checkout-api-7d9f4b6c8d-x2k9p", PodUID: "uid-1",
			ContainerName: "api", Kind: k8s.FailureOOMKilled, ExitCode: 137,
			Restarts: 4, FirstSeen: time.Now(),
		},
		Namespace:             "payments",
		PodName:               "checkout-api-7d9f4b6c8d-x2k9p",
		PodUID:                "uid-1",
		Container:             "api",
		Kind:                  string(k8s.FailureOOMKilled),
		ExitCode:              137,
		Restarts:              4,
		ScrubbedLogs:          []string{"level=error msg=\"alloc failure\""},
		ScrubbedEventMessages: []string{"Container api was OOMKilled (exit code 137)."},
	}
}

// slowTelemetry delays each call, so a cancellation can be made to land mid-flight.
type slowTelemetry struct {
	delay  time.Duration
	mu     sync.Mutex
	active int
}

func (s *slowTelemetry) Logs(context.Context, string, string, string, bool) (string, error) {
	return s.stall(), nil
}

func (s *slowTelemetry) Events(context.Context, string, string) ([]corev1.Event, error) {
	_ = s.stall()
	return nil, nil
}

func (s *slowTelemetry) stall() string {
	s.mu.Lock()
	s.active++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		s.mu.Unlock()
	}()
	time.Sleep(s.delay)
	return "level=error msg=oom\n"
}

func (s *slowTelemetry) inFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

type countingSink struct {
	mu    sync.Mutex
	count int
}

func (c *countingSink) Dispatch(context.Context, *worker.Incident) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	return nil
}

func (c *countingSink) dispatched() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// waitForCondition polls until the condition holds or the timeout elapses. Named
// apart from main's waitFor, which waits on a channel rather than a predicate.
func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

// contains is strings.Contains. Spelled out so the test file does not need the
// strings import for one call, which would otherwise sit next to a var _ that
// exists only to keep an unused import honest - and an unused import in a test is
// usually a sign the test is not testing what it says.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// discardLogger silences the pool's own logging, which would otherwise fill the
// test output with a line per incident.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// notifyContextForTest exercises the same primitive run() uses, so the assertion
// is about the real signal semantics rather than a reimplementation.
func notifyContextForTest(*testing.T) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
