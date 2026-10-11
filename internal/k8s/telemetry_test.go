package k8s

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// The fake clientset records every request as an action, and the log request
// carries the *corev1.PodLogOptions it was called with as the action's Value.
// That is how these tests prove the bounds reach the API rather than merely being
// set on a struct nobody reads: the options are inspected on the recorded action.
//
// A test asserting the constants directly (LogTailLines == 100) would pass even if
// Logs() stopped passing them, which is the regression worth catching.

// lastLogOptions returns the PodLogOptions from the most recent pod/log action.
func lastLogOptions(t *testing.T, client *fake.Clientset) *corev1.PodLogOptions {
	t.Helper()
	actions := client.Actions()
	for i := len(actions) - 1; i >= 0; i-- {
		action := actions[i]
		if action.GetVerb() != "get" || action.GetSubresource() != "log" {
			continue
		}
		opts, ok := action.(k8stesting.GenericAction).GetValue().(*corev1.PodLogOptions)
		if !ok || opts == nil {
			t.Fatalf("log action carried %T, want *corev1.PodLogOptions",
				action.(k8stesting.GenericAction).GetValue())
		}
		return opts
	}
	t.Fatal("no pod/log action was recorded; the fake client may not be intercepting")
	return nil
}

func TestLogsPassesTheBoundsToTheAPI(t *testing.T) {
	client := newFakeClient(newPod("logged", withStatus(oomKilled(1))))
	telemetry := NewTelemetry(client)

	if _, err := telemetry.Logs(newCtx(t), "payments", "logged", "checkout-api", true); err != nil {
		t.Fatalf("Logs failed: %v", err)
	}

	opts := lastLogOptions(t, client)

	// The two bounds are contract values (ARCH §7). A regression here means an
	// unbounded read, which is how a log fetch turns into an OOM.
	if opts.TailLines == nil {
		t.Fatal("TailLines was nil, which the API reads as unbounded")
	}
	if *opts.TailLines != LogTailLines {
		t.Errorf("TailLines = %d, want %d", *opts.TailLines, LogTailLines)
	}
	if opts.LimitBytes == nil {
		t.Fatal("LimitBytes was nil, which the API reads as unbounded")
	}
	if *opts.LimitBytes != LogLimitBytes {
		t.Errorf("LimitBytes = %d, want %d", *opts.LimitBytes, LogLimitBytes)
	}
	if *opts.LimitBytes != 51200 {
		t.Errorf("LimitBytes = %d, want the specified 51200 (50 KiB)", *opts.LimitBytes)
	}
	if *opts.TailLines != 100 {
		t.Errorf("TailLines = %d, want the specified 100", *opts.TailLines)
	}
	if opts.Container != "checkout-api" {
		t.Errorf("Container = %q, want checkout-api", opts.Container)
	}
}

// TestPreviousLogsForFollowsTheContainerState is the point of the Previous flag.
//
// The two incident shapes point in OPPOSITE directions, which is why this was
// wrong for two runs of the E2E detonation and why a comment that said "both
// cases need the previous instance" was never questioned:
//
//   - OOMKilled: the current instance is the one that died. `previous` must be
//     false. On a first crash there is no previous instance and the kubelet
//     errors; on a later crash it serves an older instance's log, which is
//     evidence about a different failure.
//   - CrashLoopBackOff: the current instance is one kubelet cannot start, and it
//     is blank. The dead instance is the previous one. `previous` must be true.
//
// Getting the Terminated case wrong is quiet, which is why it survived: the
// fetch fails, `Logs` returns an empty body without an error the caller treats
// as fatal, and an empty body passes "no secret survived" vacuously while
// failing "something was masked".
func TestPreviousLogsForFollowsTheContainerState(t *testing.T) {
	cases := []struct {
		kind     FailureKind
		previous bool
		why      string
	}{
		{FailureOOMKilled, false, "the current instance is the one that died"},
		{FailureCrashLoopBackOff, true, "the current instance is blank; the dead one is previous"},
		{FailureKind("Terminated"), false, "same as OOMKilled: terminated now, not waiting"},
		{FailureKind("SomethingElse"), false, "unknown shapes must not silently read the wrong instance"},
	}
	for _, tc := range cases {
		if got := PreviousLogsFor(tc.kind); got != tc.previous {
			t.Errorf("PreviousLogsFor(%q) = %v, want %v (%s)", tc.kind, got, tc.previous, tc.why)
		}
	}
}

// TestPreviousLogsForIsNotConstant is the negative control.
//
// A constant function - the bug this replaces - passes every row of the table
// above except one. Asserting the two shapes disagree is what makes the table
// a test rather than a restatement of the implementation.
func TestPreviousLogsForIsNotConstant(t *testing.T) {
	terminated := PreviousLogsFor(FailureOOMKilled)
	waiting := PreviousLogsFor(FailureCrashLoopBackOff)
	if terminated == waiting {
		t.Fatalf(
			"PreviousLogsFor returned %v for both Terminated and Waiting; one of "+
				"the two shapes is guaranteed to read the wrong container instance",
			terminated,
		)
	}
}

// TestLogsPassesTheDecidedPreviousThrough proves the decision reaches the wire,
// not just the unit under test.
func TestLogsPassesTheDecidedPreviousThrough(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kind     FailureKind
		wantPrev bool
	}{
		{"terminated", FailureOOMKilled, false},
		{"crashloop", FailureCrashLoopBackOff, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newFakeClient(newPod("prev-"+tc.name, withStatus(oomKilled(1))))
			telemetry := NewTelemetry(client)
			if _, err := telemetry.Logs(
				newCtx(t), "payments", "prev-"+tc.name, "checkout-api",
				PreviousLogsFor(tc.kind),
			); err != nil {
				t.Fatalf("Logs failed: %v", err)
			}
			if opts := lastLogOptions(t, client); opts.Previous != tc.wantPrev {
				t.Errorf("PodLogOptions.Previous = %v, want %v", opts.Previous, tc.wantPrev)
			}
		})
	}
}

func TestLogsRequestsPreviousWhenAsked(t *testing.T) {
	client := newFakeClient(newPod("live", withStatus(running(0))))
	telemetry := NewTelemetry(client)
	if _, err := telemetry.Logs(newCtx(t), "payments", "live", "checkout-api", false); err != nil {
		t.Fatalf("Logs failed: %v", err)
	}
	if opts := lastLogOptions(t, client); opts.Previous {
		t.Error("Previous = true for a running container; it would read the wrong log")
	}
}

func TestEventsUseThePodUIDFieldSelector(t *testing.T) {
	pod := newPod("joined", withStatus(oomKilled(1)))
	client := fake.NewSimpleClientset(pod, &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "evt-1"},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Pod", Namespace: "payments", Name: pod.Name, UID: pod.UID,
		},
		Message: "OOMKilled",
	})
	telemetry := NewTelemetry(client)

	events, err := telemetry.Events(newCtx(t), "payments", string(pod.UID))
	if err != nil {
		t.Fatalf("Events failed: %v", err)
	}

	// The selector must be a FieldSelector on involvedObject.uid, and it must
	// reach the recorded action. A name-based selector would pull in events from a
	// previous pod of the same name and attribute them to this one.
	var found bool
	for _, action := range client.Actions() {
		list, ok := action.(k8stesting.ListAction)
		if !ok || action.GetResource().Resource != "events" {
			continue
		}
		selector := list.GetListRestrictions().Fields.String()
		if strings.Contains(selector, "involvedObject.uid="+string(pod.UID)) {
			found = true
		} else {
			t.Errorf("event selector = %q, want it to target involvedObject.uid=%s", selector, pod.UID)
		}
	}
	if !found {
		t.Error("no event List action recorded with the expected field selector")
	}
	if len(events) == 0 {
		t.Error("Events returned nothing; the fake should have served the seeded event")
	}
}

func TestFieldSelectorEventUIDFormat(t *testing.T) {
	if got := FieldSelectorEventUID("abc-123"); got != "involvedObject.uid=abc-123" {
		t.Errorf("FieldSelectorEventUID = %q", got)
	}
}

// TestClusterEventsMaxMatchesTheAgentContract pins a cross-language bound.
//
// The agent's IncidentPayload.cluster_events is Field(max_length=CLUSTER_EVENTS_MAX)
// (agent/models.py:372 = 64) and a payload above the cap is a hard 422 - the
// incident the Sentinel worked hardest to build is discarded as invalid. Before
// Events() bounded its List, a crash-looping pod with a long event history
// produced hundreds of events and every one of them took the whole payload down.
//
// This constant is the Limit Events() passes to the API server. The agent's
// matching cap is pinned on the Python side (agent/tests/test_phase4_regressions.py
// ::test_cluster_events_cap_is_pinned_to_the_documented_value). If either side
// changes, change both.
func TestClusterEventsMaxMatchesTheAgentContract(t *testing.T) {
	if ClusterEventsMax != 64 {
		t.Errorf("ClusterEventsMax = %d, want 64 (must match agent models.CLUSTER_EVENTS_MAX)", ClusterEventsMax)
	}
}

// TestEventsWithEmptyUIDIsNotAnError: a pod deleted between the watch event and
// this call has no events to find. Failing the whole incident over that would lose
// the logs already collected.
func TestEventsWithEmptyUIDIsNotAnError(t *testing.T) {
	client := newFakeClient()
	telemetry := NewTelemetry(client)

	events, err := telemetry.Events(newCtx(t), "payments", "")
	if err != nil {
		t.Fatalf("an empty UID should not be an error, got %v", err)
	}
	if len(events) != 0 {
		t.Errorf("want no events, got %d", len(events))
	}
	// And it must not have called the API at all.
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "events" {
			t.Error("an empty UID still issued an event List")
		}
	}
}

// TestTelemetryCallsAreDeadlineBounded proves the caller's context governs the
// call: a cancelled context must fail fast rather than hang or succeed.
//
// client-go's fake does not surface the per-request context on the recorded action,
// so the deadline is proved behaviourally rather than by inspecting it. An earlier
// draft tried to read the deadline off the reactor and ended up with placeholder
// assertions that could not fail.
func TestTelemetryCallsAreDeadlineBounded(t *testing.T) {
	client := newFakeClient(newPod("deadline", withStatus(oomKilled(1))))
	telemetry := NewTelemetry(client)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := telemetry.Logs(cancelled, "payments", "deadline", "checkout-api", true)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("a cancelled context produced a successful log fetch")
	}
	if elapsed > TelemetryTimeout {
		t.Errorf("the call took %s despite a cancelled context", elapsed)
	}

	// The event List is deliberately NOT asserted here. client-go's fake serves
	// List from an in-memory tracker that ignores a cancelled context, so the
	// claim is not observable with the fake and asserting it would either fail
	// spuriously or be commented out. The timeout is applied by the same
	// context.WithTimeout call in both methods, so the Logs assertion covers the
	// mechanism; a genuine cancellation assertion needs a real apiserver.
}

// TestBoundedWriterTruncatesWithoutErroring covers the byte cap.
//
// io.Copy reports a short write as io.ErrShortWrite, which would turn a server
// exceeding LimitBytes into a failed fetch - punishing exactly the noisiest
// container, which is the one most likely to be the incident.
func TestBoundedWriterTruncatesWithoutErroring(t *testing.T) {
	var builder strings.Builder
	writer := &boundedWriter{w: &builder, remaining: 10}

	n, err := writer.Write([]byte("0123456789ABCDEF"))
	if err != nil {
		t.Errorf("Write returned an error on overflow: %v", err)
	}
	if n != 16 {
		t.Errorf("Write consumed %d of 16 bytes; io.Copy needs the full count to stop cleanly", n)
	}
	if builder.String() != "0123456789" {
		t.Errorf("kept %q, want the first 10 bytes", builder.String())
	}

	// Further writes are no-ops that still report full consumption.
	if _, err := writer.Write([]byte("more")); err != nil {
		t.Errorf("post-cap Write errored: %v", err)
	}
	if builder.String() != "0123456789" {
		t.Errorf("post-cap write appended %q", builder.String())
	}
}

func TestTelemetryWithNilClientFailsClosed(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a nil client panicked: %v", r)
		}
	}()
	telemetry := NewTelemetry(nil)
	if _, err := telemetry.Logs(newCtx(t), "payments", "p", "c", true); err == nil {
		t.Error("Logs with a nil client returned no error")
	}
	if _, err := telemetry.Events(newCtx(t), "payments", "uid"); err == nil {
		t.Error("Events with a nil client returned no error")
	}
}

// TestLogErrorDoesNotLeakCredentials: the error path must not carry a token path.
// TestLogErrorDoesNotLeakCredentials uses the injectable reader rather than a
// reactor.
//
// client-go's fake serves GetLogs from a purpose-built REST client, not the object
// tracker a PrependReactor intercepts, so a reactor never fires for a log request.
// An earlier version of this test registered one and then asserted an error that
// could not arrive - it passed for the wrong reason until the reactor was found not
// to run at all.
func TestLogErrorDoesNotLeakCredentials(t *testing.T) {
	telemetry := NewTelemetry(nil)
	telemetry.logReader = func(_, _, _ string, _ *corev1.PodLogOptions) (string, error) {
		return "", errors.New("failed to read /var/run/secrets/kubernetes.io/serviceaccount/token")
	}

	_, err := telemetry.Logs(newCtx(t), "payments", "p", "c", true)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "serviceaccount/token") {
		t.Errorf("the error leaked a credential path: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Errorf("the error was not redacted: %v", err)
	}
}

// TestRedactErrorRemovesTheCredentialNotJustTheHintWord is the regression for a
// real leak.
//
// The original implementation replaced the hint word and stopped at the next
// delimiter, so "bearer token abcdef rejected" became
// "[REDACTED] [REDACTED] abcdef rejected". That is worse than not matching: it looks
// redacted, so a reader trusts it, and the secret is still in the log.
func TestRedactErrorRemovesTheCredentialNotJustTheHintWord(t *testing.T) {
	cases := []struct {
		in    string
		leaks string
	}{
		{"bearer token abcdef123 rejected", "abcdef123"},
		{"password: hunter2", "hunter2"},
		{"api_key=sk-live-1234", "sk-live-1234"},
		{"authorization Bearer eyJhbGciOi.x.y", "eyJhbGciOi"},
	}
	for _, tc := range cases {
		got := RedactError(errors.New(tc.in))
		if strings.Contains(got, tc.leaks) {
			t.Errorf("RedactError(%q) = %q, still contains the credential %q",
				tc.in, got, tc.leaks)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("RedactError(%q) = %q, no redaction marker", tc.in, got)
		}
	}
}

// TestRedactErrorKeepsDiagnosticContext: over-masking is preferred (ARCH 6 M5),
// but the surrounding text must survive, or the log says nothing about what
// failed.
func TestRedactErrorKeepsDiagnosticContext(t *testing.T) {
	got := RedactError(errors.New("cannot list pods: forbidden"))
	if strings.Contains(got, "[REDACTED]") {
		t.Errorf("a non-credential error was redacted: %q", got)
	}
	if !strings.Contains(got, "cannot list pods") {
		t.Errorf("diagnostic context was lost: %q", got)
	}
}

func TestEventsErrorDoesNotLeakCredentials(t *testing.T) {
	client := newFakeClient()
	client.PrependReactor("list", "events", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("denied: bearer token abcdef rejected")
	})
	telemetry := NewTelemetry(client)

	_, err := telemetry.Events(newCtx(t), "payments", "uid-1")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "abcdef") {
		t.Errorf("the error leaked a token: %v", err)
	}
}
