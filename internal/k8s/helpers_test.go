package k8s

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// discardLogger silences watcher logs during tests.
//
// Not an optimisation. The informer path logs on every drop and on shutdown, and
// a test that prints 100 lines of "egress channel full" buries the actual
// failure in the output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// newCtx returns a context bounded by a test deadline.
//
// AGENTS.md §3.2: no bare context.Background() on a blocking call. A test that
// hangs is a test that reports nothing, so the deadline is what turns a deadlock
// into a failure.
func newCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// waitForSync blocks until the informer's initial list has been delivered.
//
// Without this an update can race the sync, and the test then exercises the race
// rather than the transition it claims to test.
//
// Takes only the watcher: the client is not consulted, because HasSynced is the
// informer's own answer and is the thing worth waiting on.
// drainOne returns the next record available without blocking, or nil.
//
// A non-blocking receive: the tests that use it are asserting an *absence*, and a
// blocking receive would hang rather than fail.
func drainOne(events <-chan *IncidentRecord) *IncidentRecord {
	select {
	case record := <-events:
		return record
	default:
		return nil
	}
}

// waitForStore blocks until the informer's cache holds a pod in the given phase.
//
// Proves the update reached the handler before the test asserts on the channel,
// which is what lets a negative assertion be meaningful without a fixed sleep.
func waitForStore(
	t *testing.T,
	watcher *PodWatcher,
	namespace, name string,
	phase corev1.PodPhase,
) {
	t.Helper()
	// cache.MetaNamespaceKeyFunc formats keys as "<namespace>/<name>". Getting
	// this backwards makes the wait time out rather than fail fast, which is why
	// the ordering is worth stating.
	key := namespace + "/" + name
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		obj, exists, err := watcher.informer.GetStore().GetByKey(key)
		if err != nil {
			t.Fatalf("store lookup failed: %v", err)
		}
		if exists {
			if pod, isPod := obj.(*corev1.Pod); isPod && pod.Status.Phase == phase {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("informer never stored %s in phase %s", key, phase)
}

// waitForStats blocks until the watcher reports at least the given counts.
//
// PodWatcher.Stats() is documented as NOT atomic across counters: it snapshots
// four counters that the Run goroutine increments independently. A test that
// reads them straight after delivering an object therefore races - it can read
// Emitted before the Run goroutine has incremented it, even though the incident
// has already been handed to the channel. Under `-race` that surfaced as a
// spurious "Emitted = 0, want 1" roughly one run in eight.
//
// Waiting on the counts is what makes the assertion about the invariant rather
// than about scheduling; the exact-value assertions that follow are unchanged,
// so a watcher that emits twice or suppresses nothing still fails.
func waitForStats(t *testing.T, watcher *PodWatcher, emitted, suppressed uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		stats := watcher.Stats()
		if stats.Emitted >= emitted && stats.DedupSuppressed >= suppressed {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	stats := watcher.Stats()
	t.Fatalf(
		"watcher never reported Emitted >= %d and DedupSuppressed >= %d; last saw emitted=%d suppressed=%d",
		emitted,
		suppressed,
		stats.Emitted,
		stats.DedupSuppressed,
	)
}

func waitForSync(t *testing.T, watcher *PodWatcher) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if watcher.informer != nil && watcher.informer.HasSynced() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("informer never synced")
}
