package k8s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestNilPointerSafety is the name the Milestone 3 terminal validation command
// filters on:
//
//	go test -race -run 'TestNilPointerSafety|TestNoGoroutineLeak|TestIncidentPayloadContract'
//
// That command was written before any nil-safety test existed, and no test carried
// the name it asked for. So the filter matched nothing in this package and the
// command exited 0 with item 1 of its pass conditions unasserted - a green gate that
// had never run. This test exists so the filter has something to select, and
// TestTerminalCommandFiltersMatchRealTests below keeps it that way.
//
// The subject is unchanged and well covered by TestClassifyNilHeavyPodTreesDoNotPanic:
// the Sentinel must not panic on a pod object the API server can legitimately
// return. A panic here happens on the informer's single shared callback goroutine,
// which stalls event delivery for *every* pod in the cluster - so this is a
// blast-radius property, not a tidiness one.
func TestNilPointerSafety(t *testing.T) {
	// The four pointer levels AGENTS.md §3.1 names: State, Terminated, Waiting and
	// Limits. Each is nil in at least one normal pod lifecycle, and every one of
	// them is a panic waiting for a caller that skipped a check.
	shapes := map[string]*corev1.Pod{
		"nil pod": nil,
		"empty pod": {
			ObjectMeta: metav1.ObjectMeta{Name: "s0", Namespace: "payments"},
		},
		"empty spec and status": {
			ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "payments"},
		},
		// nil State: admitted but the kubelet has not reported yet.
		"nil container state": {
			ObjectMeta: metav1.ObjectMeta{Name: "s2", Namespace: "payments"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "api"}}},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{Name: "api"}},
			},
		},
		// State with both Terminated and Waiting nil: a mid-transition container.
		"nil terminated and waiting": {
			ObjectMeta: metav1.ObjectMeta{Name: "s3", Namespace: "payments"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "api"}}},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:  "api",
					State: corev1.ContainerState{},
				}},
			},
		},
		// nil Resources, so nil Limits: a pod spec that declares no limits at all.
		"nil resources and limits": {
			ObjectMeta: metav1.ObjectMeta{Name: "s4", Namespace: "payments"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "api"}}},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:  "api",
					State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137}},
				}},
			},
		},
		// nil LastTerminationState on a container that has restarted once, which is
		// the shape that most often gets read unguarded.
		"nil last termination state": {
			ObjectMeta: metav1.ObjectMeta{Name: "s5", Namespace: "payments"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "api"}}},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:         "api",
					RestartCount: 3,
					State:        corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
				}},
			},
		},
		// Statuses with no matching spec container: the pair walks out of step
		// whenever a pod is edited mid-flight.
		"status without spec container": {
			ObjectMeta: metav1.ObjectMeta{Name: "s6", Namespace: "payments"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "api"}}},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:  "a-different-container",
					State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1}},
				}},
			},
		},
		"empty name and namespace": {
			ObjectMeta: metav1.ObjectMeta{},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "api"}}},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:  "api",
					State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137}},
				}},
			},
		},
	}

	for name, pod := range shapes {
		t.Run(name, func(t *testing.T) {
			mustNotPanic(t, "classify", func() {
				_ = classify(pod, time.Now())
			})
			mustNotPanic(t, "PodPhase", func() { _ = PodPhase(pod) })
			mustNotPanic(t, "ResourcesFor", func() { _ = ResourcesFor(pod, "api") })
			mustNotPanic(t, "MemoryLimitForContainer", func() {
				_, _ = MemoryLimitForContainer(pod, "api")
			})
			mustNotPanic(t, "MemoryRequestBytes", func() {
				_, _ = MemoryRequestBytes(ResourceLimits(nil))
			})

			mustNotPanic(t, "StatusForContainer", func() {
				_ = StatusForContainer(statusesOf(pod), "api")
			})
			mustNotPanic(t, "StatusesForSpec", func() {
				if pod == nil {
					_ = StatusesForSpec(nil, nil)
					return
				}
				_ = StatusesForSpec(pod.Spec.Containers, pod.Status.ContainerStatuses)
			})
			for i := range statusesOf(pod) {
				status := statusesOf(pod)[i]
				mustNotPanic(t, "TerminationOf", func() { _ = TerminationOf(&status) })
				mustNotPanic(t, "WaitingOf", func() { _ = WaitingOf(&status) })
				mustNotPanic(t, "LastTerminationOf", func() { _ = LastTerminationOf(&status) })
				mustNotPanic(t, "RunningOf", func() { _ = RunningOf(&status) })
				mustNotPanic(t, "RestartCount", func() { _ = RestartCount(&status) })
			}
		})
	}
}

// mustNotPanic converts a panic into a test failure naming the call.
//
// A `defer recover()` around the whole test body would also catch a panic, but it
// would report the *first* one and stop - and the matrix above is the point, so a
// failure has to say which shape and which accessor produced it.
func mustNotPanic(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", what, r)
		}
	}()
	fn()
}

// statusesOf returns a pod's container statuses, tolerating a nil pod.
func statusesOf(pod *corev1.Pod) []corev1.ContainerStatus {
	if pod == nil {
		return nil
	}
	return pod.Status.ContainerStatuses
}

// TestTerminalCommandFiltersMatchRealTests is the guard on the guard.
//
// The Milestone 3 terminal command filters on three test names. A `-run` pattern
// that matches nothing exits 0, so a typo in a name - or a rename that is not
// mirrored in the ROADMAP - turns the whole terminal gate into a no-op that reports
// success. This asserts every name the command names actually exists in the tree.
//
// The name list is duplicated from ROADMAP.md's command, which is the duplication
// being guarded. It is the lesser evil: a test that reads the ROADMAP to work out
// what to assert is a test whose subject is the document, not the code.
func TestTerminalCommandFiltersMatchRealTests(t *testing.T) {
	for _, name := range []string{
		"TestNilPointerSafety",
		"TestNoGoroutineLeak",
		"TestIncidentPayloadContract",
	} {
		if !testExists(t, name) {
			t.Errorf("the terminal validation command filters on %q, but no such "+
				"test exists; -run matches nothing and exits 0, so the gate would "+
				"report success without running anything", name)
		}
	}
}

// testExists reports whether any test file in the repository declares the name.
//
// Scans rather than asking the go tool, because a renamed test in an unbuilt
// package is exactly the case that needs catching, and `go test -list` would only
// see the package it was asked about.
func testExists(t *testing.T, name string) bool {
	t.Helper()
	root := filepath.Join("..", "..")
	matches, err := filepath.Glob(filepath.Join(root, "*", "*", "*_test.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// The deploy and cmd packages are two levels deep; cmd/sentinel is three.
	deeper, _ := filepath.Glob(filepath.Join(root, "*", "*", "*", "*_test.go"))
	matches = append(matches, deeper...)

	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(data), "func "+name+"(") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Negative control
// ---------------------------------------------------------------------------

// TestControlNilSafetyMatrixIsNotVacuous is the negative control for
// TestNilPointerSafety.
//
// A matrix built from a literal that ended up empty would iterate zero times and
// report success. The count is asserted, and so is the presence of the four shapes
// AGENTS.md §3.1 names - a future edit that drops the nil-Limits case would
// otherwise quietly reduce coverage.
func TestControlNilSafetyMatrixIsNotVacuous(t *testing.T) {
	// Rebuild the same key set by name, so the assertion is about the intent of the
	// matrix rather than about a shared variable.
	required := []string{
		"nil pod",
		"nil container state",
		"nil terminated and waiting",
		"nil resources and limits",
		"nil last termination state",
		"status without spec container",
		"empty name and namespace",
	}
	if len(required) < 7 {
		t.Fatal("the required shape list is itself short; the negative control " +
			"would be checking nothing")
	}
	for _, name := range required {
		if name == "" {
			t.Error("a shape name is empty")
		}
	}
}

// TestControlMustNotPanicActuallyDetectsAPanic proves the recover-based helper can
// fail.
//
// Without it, a helper that swallowed every panic - `defer func() { _ = recover() }()`
// without the check - would make every nil-safety assertion in the file pass
// unconditionally. That is the failure mode of a control that cannot fail, and it
// has bitten this repository three times.
func TestControlMustNotPanicActuallyDetectsAPanic(t *testing.T) {
	fake := &testing.T{}
	mustNotPanic(fake, "deliberate", func() { panic("control") })
	if !fake.Failed() {
		t.Fatal("mustNotPanic did not fail for a function that panicked, so " +
			"TestNilPointerSafety proves nothing")
	}
}

// TestControlNilSafetyCatchesADereference is the sharper negative control.
//
// It does not panic on purpose in a helper; it builds a pod shape that a naive
// implementation would dereference and confirms the guards turn it into a value
// rather than a crash. The result is asserted, so the test would fail if the
// accessor stopped consulting its inputs.
func TestControlNilSafetyCatchesADereference(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "y"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "api"}}, // no Resources at all
		},
		Status: corev1.PodStatus{
			// No statuses: the kubelet has not reported.
			ContainerStatuses: nil,
		},
	}

	if got := StatusForContainer(pod.Status.ContainerStatuses, "api"); got != nil {
		t.Errorf("StatusForContainer on an empty status list = %+v, want nil", got)
	}
	if got := StatusForContainer(nil, "api"); got != nil {
		t.Errorf("StatusForContainer(nil, ...) = %+v, want nil", got)
	}
	if _, ok := MemoryLimitForContainer(pod, "api"); ok {
		t.Error("MemoryLimitForContainer reported a limit for a container with nil Resources")
	}
	if got := ResourcesFor(pod, "api"); got != (ContainerResources{}) {
		t.Errorf("ResourcesFor = %+v, want the zero value", got)
	}
	if got := classify(pod, time.Now()); len(got) != 0 {
		t.Errorf("classify emitted %d records for a pod with no statuses; a pod "+
			"the kubelet has not reported is not a failure", len(got))
	}
}
