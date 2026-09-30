package emitter

import (
	"testing"

	"github.com/srek3s/sentinel/internal/k8s"
	"github.com/srek3s/sentinel/internal/worker"
)

// TestExitCodePresenceIsTheInverseOfPreviousLogs is the invariant that makes
// PreviousLogsFor's implementation detail invisible.
//
// The rule is "an incident that carries an exit code is terminated now, so its
// logs are the current instance's; an incident without one is waiting to
// restart, so its logs are the previous instance's". exitCodeFor decides the
// first half and PreviousLogsFor decides the second, in different packages,
// keyed on the same field by different means - a Kind comparison in one and a
// Kind switch in the other. Nothing forced them to agree, and they did not:
// PreviousLogsFor returned true for OOMKilled, so a terminated incident asked
// the kubelet for an instance that was not the one that died.
//
// Two predicates on the same input must be inverses. Asserted rather than
// assumed, because the failure is quiet: the fetch returns an empty body, no
// secret survives in it, and the redaction check then reports that nothing was
// masked on a pipeline that is working perfectly.
func TestExitCodePresenceIsTheInverseOfPreviousLogs(t *testing.T) {
	for _, tc := range []struct {
		kind        string
		wantExitSet bool
		wantPrevLog bool
	}{
		{ReasonOOMKilled, true, false},
		{ReasonCrashLoopBackOff, false, true},
	} {
		incident := &worker.Incident{
			Kind:     tc.kind,
			ExitCode: 137,
			Record:   &k8s.IncidentRecord{Kind: k8s.FailureKind(tc.kind), ExitCode: 137},
		}
		_, hasExit := exitCodeFor(incident)
		if hasExit != tc.wantExitSet {
			t.Errorf("%s: exitCodeFor reported exit present=%v, want %v",
				tc.kind, hasExit, tc.wantExitSet)
		}
		gotPrev := k8s.PreviousLogsFor(k8s.FailureKind(tc.kind))
		if gotPrev != tc.wantPrevLog {
			t.Errorf("%s: PreviousLogsFor = %v, want %v", tc.kind, gotPrev, tc.wantPrevLog)
		}
		if hasExit == gotPrev {
			t.Errorf(
				"%s: an incident with exitCode present=%v must NOT request the "+
					"previous instance (got Previous=%v); the two predicates are "+
					"supposed to be inverses",
				tc.kind, hasExit, gotPrev,
			)
		}
	}
}

// TestPreviousLogsForIsNotConstant is the negative control for the table above.
//
// The bug this replaces returned true for every kind the watcher emits, so a
// table asserting the correct per-kind values catches it - but only if the two
// shapes are required to disagree. Without that, adding a kind to the
// "always true" list would pass every row.
func TestPreviousLogsForIsNotConstant(t *testing.T) {
	if k8s.PreviousLogsFor(k8s.FailureOOMKilled) ==
		k8s.PreviousLogsFor(k8s.FailureCrashLoopBackOff) {
		t.Fatal(
			"PreviousLogsFor is the same for Terminated and Waiting; one of the " +
				"two shapes will read the wrong container instance's log",
		)
	}
}
