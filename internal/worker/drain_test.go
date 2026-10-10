package worker

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/srek3s/sentinel/internal/k8s"
)

// The pass that found this: a pool with seven queued incidents exited 56ms after a
// SIGTERM against a 20s grace, reporting processed:0, failed:7. ShutdownGrace was
// decorative, because handle derived each incident's context from the run context
// that the signal cancels. Seven incidents were classified, scrubbed and emitted
// into a log nobody will read, then discarded by the process exit.
//
// These tests pin the two halves of the fix, because either alone would be a
// plausible-looking lie:
//
//   - work already STARTED survives the signal and finishes;
//   - work not yet started is still refused, promptly.
//
// The second is the half that could have been broken by the fix. An unbounded
// "drain everything" would pass the first test and turn a 20s grace into however
// long the backlog takes.

// slowTelemetry holds each call open for delay, unless its context dies first.
//
// The context check is the whole experiment: it returns early on cancellation, so
// an incident that descends from the run context returns instantly and the test
// sees a truncated fetch rather than a completed one.
type slowTelemetry struct {
	delay time.Duration

	mu       sync.Mutex
	started  int
	cuts     int
	finished int
	// gate, when non-nil, holds every fetch open until it is closed. Set it only
	// in the test that needs a worker pinned mid-incident; left nil elsewhere.
	gate chan struct{}
}

func newSlowTelemetry(delay time.Duration) *slowTelemetry {
	return &slowTelemetry{delay: delay}
}

func (s *slowTelemetry) Logs(ctx context.Context, _, _, _ string, _ bool) (string, error) {
	s.mu.Lock()
	s.started++
	s.mu.Unlock()

	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		s.mu.Lock()
		s.cuts++
		s.mu.Unlock()
		return "", ctx.Err()
	}
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			s.mu.Lock()
			s.cuts++
			s.mu.Unlock()
			return "", ctx.Err()
		}
	}

	s.mu.Lock()
	s.finished++
	s.mu.Unlock()
	return `ts=... level=error msg="alloc failure"`, nil
}

func (s *slowTelemetry) Events(ctx context.Context, _, _ string) ([]corev1.Event, error) {
	if err := ctx.Err(); err != nil {
		s.mu.Lock()
		s.cuts++
		s.mu.Unlock()
		return nil, err
	}
	return nil, nil
}

func (s *slowTelemetry) counts() (started, finished, cuts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started, s.finished, s.cuts
}

// The regression itself. An incident in progress when the signal arrives runs to
// completion, and the pool does not report Wait() as done until it has.
func TestAnIncidentInFlightSurvivesTheSignalAndCompletes(t *testing.T) {
	t.Parallel()

	delay := 250 * time.Millisecond
	telemetry := newSlowTelemetry(delay)
	sink := &recordingSink{}

	records := make(chan *k8s.IncidentRecord, 4)
	records <- record("checkout-api-1", "checkout-api", k8s.FailureOOMKilled)

	pool := New(records, telemetry, sink, 1,
		WithPerIncidentTimeout(30*time.Second))

	run, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool.Start(run)

	// Wait until the incident is genuinely inside the telemetry fetch, so the
	// signal lands mid-flight rather than before the worker picks the record up.
	// Without this the test can pass by cancelling first and starting second, which
	// is not the bug.
	waitFor(t, 5*time.Second, func() bool {
		started, _, _ := telemetry.counts()
		return started > 0
	})

	cancelAt := time.Now()
	cancel()

	drained := make(chan struct{})
	go func() {
		pool.Wait()
		close(drained)
	}()

	select {
	case <-drained:
	case <-time.After(10 * time.Second):
		t.Fatal("Wait() did not return; the pool is wedged")
	}
	elapsed := time.Since(cancelAt)

	if got := len(sink.all()); got != 1 {
		t.Fatalf("dispatched %d incidents, want 1: the in-flight one was dropped by the signal", got)
	}
	if _, finished, cuts := telemetry.counts(); finished != 1 || cuts != 0 {
		t.Errorf("telemetry finished=%d cut=%d, want 1 and 0: the run context "+
			"reached work in progress", finished, cuts)
	}
	if pool.Stats().Processed != 1 {
		t.Errorf("Processed = %d, want 1", pool.Stats().Processed)
	}
	if pool.Stats().Failed != 0 {
		t.Errorf("Failed = %d, want 0", pool.Stats().Failed)
	}
	// The drain must have waited for the work rather than raced past it. Without
	// this bound the assertions above could all hold on a pool that gave up
	// instantly and let a stray goroutine finish the job later.
	if elapsed < delay/2 {
		t.Errorf("Wait() returned %v after the signal; the incident had %v left to "+
			"run, so the drain did not actually wait for it", elapsed, delay)
	}
}

// The other half. Workers must still stop taking new work the instant the signal
// arrives, or a graceful shutdown is just a slower crash.
//
// The channel is CLOSED here on purpose. A select with both arms ready picks
// pseudo-randomly, so a worker returning from an incident into a queue that still
// has records in it would take one about half the time - and this test would be a
// coin flip rather than a test. Closing the channel makes the drain deterministic:
// the only way to reach record 2 is to accept it after the signal.
func TestWorkersStopTakingNewWorkAtTheSignal(t *testing.T) {
	t.Parallel()

	// Repeated, because the property under test is "deterministic", and a single
	// run cannot prove that.
	//
	// The scenario is one worker holding one incident and a second one still queued
	// when the signal lands. With the run context checked before the select, the
	// worker refuses the queued record every time. Without that check the two select
	// arms are both ready and Go picks between them at random, so the record is
	// taken about half the time - and a test that takes it half the time passes by
	// luck about half the time too.
	//
	// Two measurements behind the count. A standalone select over a closed ctx.Done()
	// and a closed channel holding one buffered item split 100187/99813 over 200k
	// trials: genuinely uniform. And this test against the mutant that removes the
	// pre-select check failed 247, 231, 273, 253, 242, 250, 252, 265, 245 and 256 of
	// 500 subtests across ten runs - a clean sweep has probability 2^-500.
	//
	// Worth recording how the first version of this note got it wrong: it claimed
	// the mutant survived five runs in a row and concluded the scheduling was biased.
	// It was not biased. The measurement script applied the mutant once and
	// restored it after the first attempt, so the remaining five runs were against
	// fixed code. The test was fine; the harness was not.
	const iterations = 500

	for i := range iterations {
		t.Run(fmt.Sprintf("iteration_%02d", i), func(t *testing.T) {
			t.Parallel()

			// The first record is held inside the telemetry fetch, so the worker is
			// busy when the signal arrives rather than parked in the select - which
			// is the case that reaches the pre-select check at the top of the loop.
			telemetry := newSlowTelemetry(0)
			telemetry.gate = make(chan struct{})
			sink := &recordingSink{}

			records := make(chan *k8s.IncidentRecord, 4)
			records <- record("checkout-api-1", "checkout-api", k8s.FailureOOMKilled)
			records <- record("checkout-api-2", "checkout-api", k8s.FailureOOMKilled)
			close(records)

			pool := New(records, telemetry, sink, 1,
				WithPerIncidentTimeout(30*time.Second))

			run, cancel := context.WithCancel(context.Background())
			pool.Start(run)

			waitFor(t, 5*time.Second, func() bool {
				started, _, _ := telemetry.counts()
				return started > 0
			})

			cancel()
			// The in-flight incident is now protected by handle's stripped context, so
			// release it explicitly and let the pool drain.
			close(telemetry.gate)

			drained := make(chan struct{})
			go func() {
				pool.Wait()
				close(drained)
			}()
			select {
			case <-drained:
			case <-time.After(10 * time.Second):
				t.Fatal("Wait() did not return")
			}
			cancel()

			if got := len(sink.all()); got != 1 {
				t.Fatalf("dispatched %d incidents, want 1: a worker took a queued "+
					"record after the signal, so new work was still accepted", got)
			}
			if started, _, _ := telemetry.counts(); started != 1 {
				t.Errorf("telemetry started %d fetches, want 1", started)
			}
			// Refused work must be visible. A drop that leaves no trace is the
			// outcome this whole drain exists to prevent, so it is counted.
			if got := pool.Stats().Dropped; got != 1 {
				t.Errorf("Dropped = %d, want 1: the incident refused at shutdown left "+
					"no trace anywhere", got)
			}
			if got := pool.Stats().Processed; got != 1 {
				t.Errorf("Processed = %d, want 1", got)
			}
		})
	}
}

// The bound that replaces the cancellation is not "no bound". An incident whose
// fetch outlasts the per-incident timeout must still be cut, and the process must
// still get past it. Without this the fix would read as "work is never abandoned",
// which is not true and not wanted.
func TestThePerIncidentTimeoutStillAppliesWithoutTheRunContext(t *testing.T) {
	t.Parallel()

	telemetry := newSlowTelemetry(30 * time.Second)
	sink := &recordingSink{}

	records := make(chan *k8s.IncidentRecord, 1)
	records <- record("checkout-api-1", "checkout-api", k8s.FailureOOMKilled)

	pool := New(records, telemetry, sink, 1,
		WithPerIncidentTimeout(200*time.Millisecond))

	run, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool.Start(run)

	start := time.Now()
	// The fetch is cut by the per-incident deadline alone: the run context is
	// still live here, so nothing else could be doing it.
	waitFor(t, 5*time.Second, func() bool {
		_, _, cuts := telemetry.counts()
		return cuts > 0
	})
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("the fetch was cut after %v, so perIncidentTimeout is not the "+
			"thing that cut it", elapsed)
	}

	// Now let the worker return. It is parked on an empty channel waiting for work
	// that will never come, which is correct - Wait cannot be expected to return
	// until the run context is cancelled.
	cancel()
	drained := make(chan struct{})
	go func() {
		pool.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("a hung fetch was not bounded by perIncidentTimeout once the run " +
			"context was stripped; WithoutCancel must not have removed the deadline")
	}

	// The cut logs a warning and dispatches without logs rather than failing the
	// incident, which is the long-standing behaviour for a telemetry gap.
	if pool.Stats().InFlight != 0 {
		t.Errorf("InFlight = %d after Wait(), want 0", pool.Stats().InFlight)
	}
	if got := len(sink.all()); got != 1 {
		t.Errorf("dispatched %d incidents, want 1", got)
	}
}

// ShutdownGrace in main.go is only meaningful if a pool can actually still be
// busy when the signal arrives. This is the shape main relies on, asserted from
// the pool's side: several workers, several incidents, one signal.
func TestAShutdownMidBacklogLeavesNothingRunning(t *testing.T) {
	t.Parallel()

	telemetry := newSlowTelemetry(50 * time.Millisecond)
	sink := &recordingSink{}

	records := make(chan *k8s.IncidentRecord, 8)
	for i := range 7 {
		records <- record("checkout-api-"+string(rune('a'+i)), "checkout-api", k8s.FailureOOMKilled)
	}

	pool := New(records, telemetry, sink, 4,
		WithPerIncidentTimeout(30*time.Second))

	run, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool.Start(run)

	waitFor(t, 5*time.Second, func() bool {
		_, finished, _ := telemetry.counts()
		return finished > 0
	})

	cancel()

	drained := make(chan struct{})
	go func() {
		pool.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(10 * time.Second):
		t.Fatal("Wait() did not return after the signal")
	}

	// Whatever the split between dispatched and dropped, no fetch may have been cut
	// short by the signal. That was the defect: 7 started, 7 cut, 0 finished.
	if _, finished, cuts := telemetry.counts(); cuts > 0 {
		t.Errorf("%d of %d fetches were cut by the signal; the run context reached "+
			"work in progress", cuts, finished+cuts)
	}
	if pool.Stats().InFlight != 0 {
		t.Errorf("InFlight = %d after Wait(), want 0", pool.Stats().InFlight)
	}
	if got := pool.Stats().Processed + pool.Stats().Failed; got == 0 {
		t.Error("every incident vanished: nothing processed and nothing failed")
	}
}
