// Namespace isolation guard (ROADMAP 4.1.5).
//
// The blast-radius claim this file tests is narrow and load-bearing: when the
// Sentinel is pointed at one namespace, a container failing in a *different*
// namespace must never produce an incident.
//
// Why it needs to exist as code rather than as a config review: before
// Milestone 4, `-namespace` was read, logged, and never applied. The informer was
// built unconditionally with `NewSharedInformerFactory`, which watches every
// namespace, so the startup log said "scoping the watch" over a watcher that was
// watching the whole cluster. Nothing failed. The log was simply untrue, and
// nothing in the repository would have noticed.
//
// The test that would have caught it asserts the scope reaches the *informer*,
// not the output. Filtering after the fact would also produce the right answer
// while still paying to watch every pod, so an output-only assertion would let a
// future refactor reintroduce the cost while keeping the behaviour.
package k8s

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// listNamespaces returns the namespaces the fake clientset was asked to list.
//
// Read off the recorded actions rather than off the watcher's output, because the
// two are different claims: "the informer never fetched the other namespace" and
// "the other namespace's incidents were filtered out" are not the same guarantee,
// and only the first is a blast-radius control.
func listNamespaces(t *testing.T, client *fake.Clientset) []string {
	t.Helper()
	var namespaces []string
	for _, action := range client.Actions() {
		list, ok := action.(interface{ GetNamespace() string })
		if !ok {
			continue
		}
		if action.GetVerb() != "list" && action.GetVerb() != "watch" {
			continue
		}
		namespaces = append(namespaces, list.GetNamespace())
	}
	return namespaces
}

// TestNamespaceScopeReachesTheInformer is the positive claim: a scoped watcher
// only ever lists and watches that namespace.
func TestNamespaceScopeReachesTheInformer(t *testing.T) {
	const target = "sentinel-chaos"

	client := fake.NewSimpleClientset()
	watcher := NewPodWatcher(client, WithNamespace(target))

	stop := make(chan struct{})
	defer close(stop)
	go watcher.Run(stop)

	// The informer connects asynchronously; wait for the first List rather than
	// sleeping a fixed interval, or the assertion races the informer rather than
	// testing it.
	waitFor(t, 5*time.Second, func() bool {
		return len(listNamespaces(t, client)) > 0
	})

	for _, namespace := range listNamespaces(t, client) {
		if namespace != target {
			t.Errorf("informer listed/watched namespace %q while scoped to %q; "+
				"the scope is being applied after the fact, so the cost of "+
				"watching the whole cluster is still being paid", namespace, target)
		}
	}
}

// TestUnscopedWatcherIsClusterWide pins the permissive default.
//
// This is a safety assertion in the opposite direction. An empty namespace means
// "all namespaces" by client-go's convention, and if that ever changed to mean
// "the empty namespace", a default-constructed Sentinel would silently watch
// nothing - the failure mode of a monitoring tool is silence, and silence looks
// exactly like a healthy cluster.
func TestUnscopedWatcherIsClusterWide(t *testing.T) {
	client := fake.NewSimpleClientset()
	watcher := NewPodWatcher(client)

	namespace, clusterWide := watcher.Namespace()
	if !clusterWide {
		t.Errorf("a watcher built with no options is scoped to %q; the zero value "+
			"must be cluster-wide", namespace)
	}
	if namespace != AllNamespaces {
		t.Errorf("namespace = %q, want the empty AllNamespaces sentinel", namespace)
	}

	stop := make(chan struct{})
	defer close(stop)
	go watcher.Run(stop)
	waitFor(t, 5*time.Second, func() bool {
		return len(listNamespaces(t, client)) > 0
	})
	// All-namespaces means the list is issued with an empty namespace, which is
	// how the API expresses "everywhere".
	for _, namespace := range listNamespaces(t, client) {
		if namespace != AllNamespaces {
			t.Errorf("an unscoped watcher listed namespace %q, want %q",
				namespace, AllNamespaces)
		}
	}
}

// TestNamespaceScopeSurvivesOptionOrder is the negative control for the option
// hazard.
//
// The first implementation had `WithResyncPeriod` rebuild the factory, so applying
// it *after* `WithNamespace` silently discarded the scope and the Sentinel widened
// back to cluster-wide. Both orders must produce the same scoped watcher; the
// ordering is not part of any caller's contract and must not be load-bearing.
func TestNamespaceScopeSurvivesOptionOrder(t *testing.T) {
	const target = "sentinel-chaos"

	orders := map[string][]WatcherOption{
		"namespace then resync": {WithNamespace(target), WithResyncPeriod(time.Minute)},
		"resync then namespace": {WithResyncPeriod(time.Minute), WithNamespace(target)},
		"namespace only":        {WithNamespace(target)},
	}
	for name, options := range orders {
		t.Run(name, func(t *testing.T) {
			watcher := NewPodWatcher(fake.NewSimpleClientset(), options...)
			namespace, clusterWide := watcher.Namespace()
			if namespace != target || clusterWide {
				t.Errorf("options %v produced namespace=%q clusterWide=%v, want %q scoped",
					name, namespace, clusterWide, target)
			}
		})
	}
}

// TestChaosNamespaceIsProcessed is the other half of 4.1.5: scoping must not be
// so tight that the chaos namespace itself is invisible.
//
// A guard that only tests exclusion is satisfied by a watcher that watches
// nothing, which is the single most expensive way for this assertion to pass.
func TestChaosNamespaceIsProcessed(t *testing.T) {
	const target = "sentinel-chaos"

	// A pod in the target namespace that is genuinely OOM-killed.
	failing := chaosPod(target, "checkout-canary", "oom-canary", 137, 1)
	// A pod elsewhere, also genuinely OOM-killed.
	outsider := chaosPod("production", "checkout-api-7d9f", "api", 137, 9)

	client := fake.NewSimpleClientset(failing, outsider)
	watcher := NewPodWatcher(client, WithNamespace(target))

	stop := make(chan struct{})
	defer close(stop)
	go watcher.Run(stop)

	// Collect everything the watcher emits, then assert on the set rather than on
	// the first record. A scoped informer may deliver the in-scope pod first, but
	// relying on that would be asserting the fake's delivery order.
	// Labelled break, and the reason is a bug this loop contained first: a
	// `break` inside a `select` case breaks the *select*, not the `for`, so an
	// expired time.After channel was re-selected on every iteration and the loop
	// spun for 64s instead of ending. A timeout that cannot end its own wait is
	// not a timeout.
	seen := map[string]bool{}
	grace := time.NewTimer(1 * time.Second)
	defer grace.Stop()
	overall := time.NewTimer(10 * time.Second)
	defer overall.Stop()
collect:
	for {
		select {
		case record, ok := <-watcher.Events():
			if !ok {
				t.Fatalf("events channel closed early; saw %v", seen)
			}
			seen[record.Namespace] = true
			if len(seen) > 1 {
				break collect
			}
			// One in-scope pod has arrived. Nothing more is expected, but an
			// out-of-scope emission is - so keep listening for a short grace rather
			// than asserting on the first record. The grace is a second, not the
			// full timeout: waiting out the whole deadline on a passing run makes
			// the suite slow enough that people stop running it.
			if !grace.Stop() {
				<-grace.C
			}
			grace.Reset(1 * time.Second)
		case <-grace.C:
			// Quiet for a second after a delivery: nothing more is coming.
			break collect
		case <-overall.C:
			// Nothing at all was delivered. Falling through to the assertions gives
			// a readable failure instead of a bare timeout.
			break collect
		}
	}

	if !seen[target] {
		t.Errorf("no incident emitted for the watched namespace %q; the chaos "+
			"fixture would be invisible and the isolation guard would pass by "+
			"watching nothing", target)
	}
	if seen["production"] {
		t.Error("an incident was emitted for a pod outside the watched namespace; " +
			"this is the blast-radius failure 4.1.5 exists to prevent")
	}
	if len(seen) > 1 {
		t.Errorf("emitted from %d namespaces, want only %q: %v", len(seen), target, seen)
	}
}

// TestClassifyStillRunsPerNamespace is the negative control for the filter.
//
// Asserted directly on `classify`, bypassing the informer entirely: if the guard
// above ever passed because `classify` stopped producing records for some
// namespace, the guard would be measuring a classifier regression rather than
// isolation. Classification is namespace-agnostic by design and this pins it.
func TestClassifyStillRunsPerNamespace(t *testing.T) {
	for _, namespace := range []string{"sentinel-chaos", "production", "default"} {
		pod := chaosPod(namespace, "checkout-canary", "oom-canary", 137, 1)
		records := classify(pod, time.Now())
		if len(records) != 1 {
			t.Errorf("classify in namespace %q produced %d records, want 1; "+
				"classification must not depend on the namespace", namespace, len(records))
			continue
		}
		if records[0].Namespace != namespace {
			t.Errorf("record namespace = %q, want %q", records[0].Namespace, namespace)
		}
	}
}

// TestDedupKeyIsNamespaceIndependent is the check that isolation is enforced
// above the dedup cache.
//
// The dedup key is `<podUID>/<container>:<restartCount>` and deliberately carries
// no namespace. If isolation were implemented by mutating the key rather than by
// scoping the informer, two identically-named containers in different namespaces
// would still be distinct (UIDs differ), so this documents the reasoning: the
// scope is not the key's job.
func TestDedupKeyIsNamespaceIndependent(t *testing.T) {
	a := DedupKeyFor("uid-a", "api", 3)
	b := DedupKeyFor("uid-b", "api", 3)
	if a == b {
		t.Errorf("two different pod UIDs produced the same key %q", a)
	}
	if got := DedupKeyFor("uid-a", "api", 3); got != a {
		t.Errorf("DedupKeyFor is not deterministic: %q then %q", a, got)
	}
	if strings.Contains(a, "sentinel-chaos") || strings.Contains(a, "production") {
		t.Errorf("key %q embeds a namespace; isolation is the informer's job", a)
	}
}

// chaosPod builds a minimal pod that is deterministically OOMKilled.
func chaosPod(namespace, podName, container string, exitCode, restarts int32) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			UID:       apitypes.UID("uid-" + namespace + "-" + podName),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: container}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:         container,
				RestartCount: restarts,
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: exitCode,
						Reason:   "OOMKilled",
					},
				},
			}},
		},
	}
}

// waitFor polls a condition against a deadline.
//
// A fixed sleep here would race the informer's initial List, and a test that
// passes because the informer happened to be fast is a test that will fail on a
// loaded CI machine and pass on a laptop.
func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}
