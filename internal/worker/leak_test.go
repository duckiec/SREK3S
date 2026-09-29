package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/srek3s/sentinel/internal/k8s"
)

// discardLogger silences the pool's per-record error logging, which would
// otherwise emit 25 lines per test run.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestNoGoroutineLeak is ROADMAP 3.5.4.
//
// Runs under -race in CI, and the race detector is not incidental: a goroutine
// that leaks *and* touches a shared counter is a data race, so this test would
// fail twice over rather than once.
//
// Counted rather than tracked by identity, because counting is the property that
// holds for code the test does not know about. A goroutine leaked by a future
// change in emitter.go is invisible to a list of expected goroutines, and visible
// to a count.
func TestNoGoroutineLeak(t *testing.T) {
	// The count is taken after a GC and a short settle so goroutines that have
	// already returned are not still visible. runtime.NumGoroutine is a snapshot,
	// and asserting against a stale baseline produces a test that fails on a busy
	// machine and passes on an idle one - which is a test that measures the host.
	settleGoroutines()
	baseline := runtime.NumGoroutine()

	for cycle := range 25 {
		leakCheckCycle(t, cycle, baseline)
	}

	settleGoroutines()
	final := runtime.NumGoroutine()
	if final > baseline {
		t.Errorf("goroutine count went from %d to %d over 25 cancel/drain cycles",
			baseline, final)
	}
}

// leakCheckCycle runs one full lifecycle: watcher channel, pool, cancellation.
func leakCheckCycle(t *testing.T, cycle int, baseline int) {
	t.Helper()
	records := make(chan *k8s.IncidentRecord, 4)
	sink := &cycleSink{}

	pool := New(records, &cycleTelemetry{}, sink, 3, WithLogger(discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)

	// Two containers in one pod, which is the shape the dedup fix was written for
	// and therefore the shape most likely to exercise a second code path.
	records <- &k8s.IncidentRecord{
		Namespace: "payments", PodName: "checkout-api-1",
		ContainerName: "api", PodUID: "uid-1",
		Kind: k8s.FailureOOMKilled, ExitCode: 137, Restarts: 1,
		DedupKey: "uid-1/api:1", FirstSeen: time.Now(),
	}
	records <- &k8s.IncidentRecord{
		Namespace: "payments", PodName: "checkout-api-1",
		ContainerName: "sidecar", PodUID: "uid-1",
		Kind: k8s.FailureCrashLoopBackOff, Restarts: 3,
		DedupKey: "uid-1/sidecar:3", FirstSeen: time.Now(),
	}

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		pool.Wait()
	}()

	// Cancel only once both records have been dispatched, so the workers really
	// were mid-flight when the cancellation landed. A cancel that arrives before
	// any work is read would pass even if the drain were broken.
	waitFor(t, 5*time.Second, func() bool { return sink.dispatched() >= 2 })
	cancel()

	select {
	case <-drained:
	case <-time.After(10 * time.Second):
		t.Fatalf("cycle %d: the pool did not drain; goroutines are stuck", cycle)
	}

	if got := sink.dispatched(); got != 2 {
		t.Fatalf("cycle %d: dispatched %d, want 2", cycle, got)
	}

	// A per-cycle ceiling. A leak of one goroutine per cycle is exactly what the
	// outer count catches, but catching it in the cycle that caused it names the
	// cycle, which is a far more useful failure message.
	settleGoroutines()
	if current := runtime.NumGoroutine(); current > baseline+2 {
		t.Fatalf("cycle %d: goroutine count %d exceeds baseline %d by more than 2",
			cycle, current, baseline)
	}
}

// TestPoolDrainDoesNotLoseInFlightWork is the assertion that makes the leak test
// mean something.
//
// A pool that dropped its work on cancellation would pass every goroutine-count
// assertion, because no goroutine is left holding anything. The two properties
// together are the requirement: exit promptly, and lose nothing.
func TestPoolDrainDoesNotLoseInFlightWork(t *testing.T) {
	// A telemetry fetcher slow enough that the cancellation reliably lands while
	// a worker is inside it. Without the delay the test would be a race between
	// the cancel and the fetch, and would pass or fail depending on scheduling.
	telemetry := &cycleTelemetry{delay: 40 * time.Millisecond}
	sink := &cycleSink{}

	records := make(chan *k8s.IncidentRecord, 1)
	pool := New(records, telemetry, sink, 2, WithLogger(discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)

	records <- &k8s.IncidentRecord{
		Namespace: "payments", PodName: "checkout-api-1",
		ContainerName: "api", PodUID: "uid-2",
		Kind: k8s.FailureOOMKilled, ExitCode: 137, Restarts: 1,
		DedupKey: "uid-2/api:1", FirstSeen: time.Now(),
	}

	waitFor(t, 5*time.Second, func() bool { return telemetry.inFlight() > 0 })
	cancel()

	drained := make(chan struct{})
	go func() { defer close(drained); pool.Wait() }()
	select {
	case <-drained:
	case <-time.After(10 * time.Second):
		t.Fatal("the pool did not drain")
	}

	if got := sink.dispatched(); got != 1 {
		t.Errorf("dispatched %d, want 1; an incident detected just before shutdown "+
			"was dropped, which is a silent gap in coverage", got)
	}
}

// TestSinkFailureDoesNotStopTheDrain is the failure-path counterpart.
//
// A worker whose dispatch returns an error must still exit its loop. The failure
// mode this guards against is a worker that treats a sink error as fatal and
// returns early - which would leak a WaitGroup Done, or worse, spin.
func TestSinkFailureDoesNotStopTheDrain(t *testing.T) {
	records := make(chan *k8s.IncidentRecord, 1)
	sink := &cycleSink{err: errors.New("agent unreachable")}

	pool := New(records, &cycleTelemetry{}, sink, 1, WithLogger(discardLogger()))
	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)

	records <- &k8s.IncidentRecord{
		Namespace: "payments", PodName: "checkout-api-1",
		ContainerName: "api", PodUID: "uid-3",
		Kind: k8s.FailureOOMKilled, ExitCode: 137, Restarts: 1,
		DedupKey: "uid-3/api:1", FirstSeen: time.Now(),
	}

	waitFor(t, 5*time.Second, func() bool { return sink.dispatched() >= 1 })
	cancel()

	drained := make(chan struct{})
	go func() { defer close(drained); pool.Wait() }()
	select {
	case <-drained:
	case <-time.After(10 * time.Second):
		t.Fatal("a sink error prevented the drain; the worker is stuck")
	}

	if got := pool.Stats().Failed; got != 1 {
		t.Errorf("Stats().Failed = %d, want 1", got)
	}
}

// TestWaitIsSafeWithoutStart is the negative control for [Pool.Wait].
//
// Shutdown paths reach for Wait in a defer or on an error branch where Start may
// never have run. A WaitGroup at zero returns immediately, and this asserts that
// rather than trusting it - the alternative is a shutdown that deadlocks only on
// the paths that were not exercised.
func TestWaitIsSafeWithoutStart(t *testing.T) {
	records := make(chan *k8s.IncidentRecord)
	pool := New(records, &cycleTelemetry{}, &cycleSink{}, 3, WithLogger(discardLogger()))

	done := make(chan struct{})
	go func() { defer close(done); pool.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait blocked on a pool that was never started")
	}
}

// TestCancellationIsHonouredBeforeReadingTheChannel proves the select, not
// deadlock-by-luck.
//
// A worker blocked on an *unconditional* receive from a channel nobody writes to
// would never see the cancellation. This closes no channel and sends nothing, so
// an unconditional receive hangs and this fails.
func TestCancellationIsHonouredBeforeReadingTheChannel(t *testing.T) {
	records := make(chan *k8s.IncidentRecord) // never written to, never closed
	pool := New(records, &cycleTelemetry{}, &cycleSink{}, 3, WithLogger(discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)
	cancel()

	drained := make(chan struct{})
	go func() { defer close(drained); pool.Wait() }()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("workers did not observe cancellation while blocked on an empty " +
			"channel; the receive is not selected against ctx.Done()")
	}
}

// TestBoundedRetriesDoNotSpin is a resource bound, not a correctness one.
//
// A dispatch that keeps failing must not become a tight loop. The pool has no
// retry of its own, so what this guards is a regression that added one without a
// bound - the shape that turns an unreachable agent into a 100% CPU process.
func TestBoundedRetriesDoNotSpin(t *testing.T) {
	records := make(chan *k8s.IncidentRecord, 1)
	sink := &cycleSink{err: errors.New("agent unreachable")}
	pool := New(records, &cycleTelemetry{}, sink, 1, WithLogger(discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool.Start(ctx)

	records <- &k8s.IncidentRecord{
		Namespace: "payments", PodName: "checkout-api-1",
		ContainerName: "api", PodUID: "uid-4",
		Kind: k8s.FailureOOMKilled, ExitCode: 137, Restarts: 1,
		DedupKey: "uid-4/api:1", FirstSeen: time.Now(),
	}

	waitFor(t, 5*time.Second, func() bool { return sink.dispatched() >= 1 })
	// One dispatch per record. A retry loop would push this higher while the
	// channel is empty.
	time.Sleep(200 * time.Millisecond)
	if got := sink.dispatched(); got != 1 {
		t.Errorf("dispatched %d times for one record; the pool is retrying on its own", got)
	}
}

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type cycleTelemetry struct {
	delay  time.Duration
	mu     sync.Mutex
	active int
}

func (c *cycleTelemetry) Logs(context.Context, string, string, string, bool) (string, error) {
	return c.stall(), nil
}

func (c *cycleTelemetry) Events(context.Context, string, string) ([]corev1.Event, error) {
	_ = c.stall()
	return nil, nil
}

func (c *cycleTelemetry) stall() string {
	if c.delay > 0 {
		c.mu.Lock()
		c.active++
		c.mu.Unlock()
		time.Sleep(c.delay)
		c.mu.Lock()
		c.active--
		c.mu.Unlock()
	}
	return "level=error msg=oom\n"
}

func (c *cycleTelemetry) inFlight() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

type cycleSink struct {
	mu    sync.Mutex
	count int
	err   error
}

func (s *cycleSink) Dispatch(context.Context, *Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	return s.err
}

func (s *cycleSink) dispatched() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func settleGoroutines() {
	// Two GCs with a yield between. runtime.GC() plus a scheduling point is what
	// makes a just-finished goroutine's stack actually released, and the count is
	// taken after that rather than immediately.
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}
