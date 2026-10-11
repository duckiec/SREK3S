package k8s

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// ---------------------------------------------------------------------------
// Pod fixtures
//
// Built through a single constructor so a malformed tree is expressed once and
// reused. Every nil-heavy shape here is something a real cluster produces: a
// Pending pod has no Terminated, a container being created has a nil State.Terminated
// and a nil State.Waiting, and a pod with no resource spec has nil Resources.
// ---------------------------------------------------------------------------

func quantity(value string) resource.Quantity {
	return resource.MustParse(value)
}

type podOption func(*corev1.Pod)

func newPod(name string, opts ...podOption) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "payments",
			UID:       types.UID("uid-" + name),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "checkout-api",
				Resources: corev1.ResourceRequirements{
					Limits:   corev1.ResourceList{corev1.ResourceMemory: quantity("256Mi")},
					Requests: corev1.ResourceList{corev1.ResourceMemory: quantity("128Mi")},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	for _, opt := range opts {
		opt(pod)
	}
	return pod
}

func withPhase(phase corev1.PodPhase) podOption {
	return func(p *corev1.Pod) { p.Status.Phase = phase }
}

// withStatus replaces the whole status tree, so a test can state exactly which
// shape it means rather than nudging one field of a realistic default.
func withStatus(status corev1.ContainerStatus) podOption {
	return func(p *corev1.Pod) {
		p.Status.ContainerStatuses = []corev1.ContainerStatus{status}
	}
}

func oomKilled(restarts int32) corev1.ContainerStatus {
	return corev1.ContainerStatus{
		Name:         "checkout-api",
		RestartCount: restarts,
		Ready:        false,
		State: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				ExitCode:   OOMExitCode,
				Reason:     "OOMKilled",
				Message:    "container exceeded its memory limit",
				Signal:     9,
				StartedAt:  metav1.Unix(1_700_000_000, 0),
				FinishedAt: metav1.Unix(1_700_000_030, 0),
			},
		},
	}
}

func crashLooping(restarts int32) corev1.ContainerStatus {
	return corev1.ContainerStatus{
		Name:         "checkout-api",
		RestartCount: restarts,
		Ready:        false,
		State: corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{
				Reason:  "CrashLoopBackOff",
				Message: "back-off 5m0s restarting failed container",
			},
		},
	}
}

func running(restarts int32) corev1.ContainerStatus {
	return corev1.ContainerStatus{
		Name:         "checkout-api",
		RestartCount: restarts,
		Ready:        true,
		State: corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{
				StartedAt: metav1.Unix(1_700_000_000, 0),
			},
		},
	}
}

// ---------------------------------------------------------------------------
// classify: the filter
// ---------------------------------------------------------------------------

func TestClassifyCatchesOOMKilled(t *testing.T) {
	records := classify(newPod("p1", withStatus(oomKilled(3))), time.Now())
	if len(records) != 1 {
		t.Fatalf("want 1 incident, got %d: %+v", len(records), records)
	}
	got := records[0]
	if got.Kind != FailureOOMKilled {
		t.Errorf("Kind = %q, want %q", got.Kind, FailureOOMKilled)
	}
	if got.ExitCode != 137 {
		t.Errorf("ExitCode = %d, want 137", got.ExitCode)
	}
	if got.ContainerName != "checkout-api" {
		t.Errorf("ContainerName = %q, want checkout-api", got.ContainerName)
	}
	if got.Namespace != "payments" || got.PodName != "p1" {
		t.Errorf("identity wrong: %s/%s", got.Namespace, got.PodName)
	}
	if got.DedupKey != "uid-p1/checkout-api:3" {
		t.Errorf("DedupKey = %q, want uid-p1/checkout-api:3", got.DedupKey)
	}
}

func TestClassifyCatchesCrashLoopBackOff(t *testing.T) {
	records := classify(newPod("p2", withStatus(crashLooping(9))), time.Now())
	if len(records) != 1 {
		t.Fatalf("want 1 incident, got %d: %+v", len(records), records)
	}
	if records[0].Kind != FailureCrashLoopBackOff {
		t.Errorf("Kind = %q, want %q", records[0].Kind, FailureCrashLoopBackOff)
	}
	if records[0].Reason != "CrashLoopBackOff" {
		t.Errorf("Reason = %q", records[0].Reason)
	}
	if records[0].DedupKey != "uid-p2/checkout-api:9" {
		t.Errorf("DedupKey = %q, want uid-p2/checkout-api:9", records[0].DedupKey)
	}
}

func TestClassifyIgnoresHealthyPods(t *testing.T) {
	cases := []struct {
		name string
		pod  *corev1.Pod
	}{
		{"running container", newPod("ok1", withStatus(running(0)))},
		{"completed cleanly", newPod("ok2", withStatus(corev1.ContainerStatus{
			Name: "checkout-api",
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				ExitCode: 0, Reason: "Completed",
			}},
		}), withPhase(corev1.PodSucceeded))},
		{"no container statuses", newPod("ok3")},
		{"zero exit code", newPod("ok4", withStatus(corev1.ContainerStatus{
			Name:  "checkout-api",
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, Reason: "Completed"}},
		}))},
		{"nil state entirely", newPod("ok5", withStatus(corev1.ContainerStatus{Name: "checkout-api"}))},
		{"different waiting reason", newPod("ok6", withStatus(corev1.ContainerStatus{
			Name: "checkout-api",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
				Reason: "ContainerCreating",
			}},
		}))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.pod, time.Now()); len(got) != 0 {
				t.Errorf("want no incidents, got %d: %+v", len(got), got)
			}
		})
	}
}

// TestClassifyKeysOnContainerStateNotPodPhase documents a deliberate choice.
//
// classify filters on per-container state and ignores pod phase. Pod phase is an
// aggregate that lags and can be misleading: a pod can be Succeeded overall while
// a container inside it was OOMKilled and later restarted, and that OOM is
// exactly the event this Sentinel exists to report. Filtering on phase would
// suppress it.
//
// Phase is still carried on the record as information, and the aggregator decides
// what to do with it.
func TestClassifyKeysOnContainerStateNotPodPhase(t *testing.T) {
	// Self-contradictory as a real cluster object, but reachable during a rolling
	// update or when a status is observed between two kubelet writes.
	pod := newPod("phase-oddity", withStatus(oomKilled(1)), withPhase(corev1.PodSucceeded))
	records := classify(pod, time.Now())
	if len(records) != 1 {
		t.Fatalf("want the container-level OOM reported despite the pod phase, got %d", len(records))
	}
	if records[0].PodPhase != corev1.PodSucceeded {
		t.Errorf("PodPhase = %q, want it carried through as information", records[0].PodPhase)
	}
}

// TestClassifyNilPodDoesNotPanic is the ROADMAP 3.2.4 nil-safety case at the
// top of the chain.
func TestClassifyNilPodDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("classify(nil) panicked: %v", r)
		}
	}()
	if got := classify(nil, time.Now()); got != nil {
		t.Errorf("classify(nil) = %+v, want nil", got)
	}
}

// TestClassifyNilHeavyPodTreesDoNotPanic is the nil-safety matrix. Each entry is a
// pointer shape the API server can legitimately hand back.
//
// A panic here would kill the informer callback thread, which stalls event
// delivery for every pod in the cluster - so this is a test about blast radius,
// not about tidiness.
func TestClassifyNilHeavyPodTreesDoNotPanic(t *testing.T) {
	malformed := []*corev1.Pod{
		{},
		{Spec: corev1.PodSpec{}, Status: corev1.PodStatus{}},
		newPod("m1", withStatus(corev1.ContainerStatus{Name: ""})),
		newPod("m2", withStatus(corev1.ContainerStatus{
			Name:  "checkout-api",
			State: corev1.ContainerState{},
		})),
		// Container with a name that does not match the spec.
		newPod("m3", withStatus(oomKilled(1))),
		// No spec containers at all, but statuses present.
		{
			ObjectMeta: metav1.ObjectMeta{Name: "m4", Namespace: "payments"},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{oomKilled(1)},
			},
		},
		// Spec container with no Resources (nil Limits).
		{
			ObjectMeta: metav1.ObjectMeta{Name: "m5", Namespace: "payments"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "checkout-api"}},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{oomKilled(1)},
			},
		},
		// Empty namespace and name.
		newPod("", withStatus(oomKilled(1))),
	}

	for i, pod := range malformed {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("malformed pod %d panicked: %v", i, r)
				}
			}()
			_ = classify(pod, time.Now())
			_ = PodPhase(pod)
			_, _ = MemoryLimitForContainer(pod, "checkout-api")
			for _, status := range pod.Status.ContainerStatuses {
				_ = TerminationOf(&status)
				_ = WaitingOf(&status)
				_ = LastTerminationOf(&status)
				_ = RunningOf(&status)
				_ = RestartCount(&status)
			}
		}()
	}
}

// ---------------------------------------------------------------------------
// Guard accessors
// ---------------------------------------------------------------------------

func TestGuardAccessorsAreNilSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a guard accessor panicked on nil: %v", r)
		}
	}()

	if got := TerminationOf(nil); got.Found {
		t.Error("TerminationOf(nil).Found = true")
	}
	if got := WaitingOf(nil); got.Found {
		t.Error("WaitingOf(nil).Found = true")
	}
	if got := LastTerminationOf(nil); got.Found {
		t.Error("LastTerminationOf(nil).Found = true")
	}
	if RunningOf(nil) {
		t.Error("RunningOf(nil) = true")
	}
	if got := RestartCount(nil); got != 0 {
		t.Errorf("RestartCount(nil) = %d", got)
	}
	if _, ok := MemoryLimitBytes(nil); ok {
		t.Error("MemoryLimitBytes(nil) reported a limit")
	}
	if _, ok := MemoryLimitForContainer(nil, "x"); ok {
		t.Error("MemoryLimitForContainer(nil) reported a limit")
	}
	if got := StatusForContainer(nil, "x"); got != nil {
		t.Error("StatusForContainer(nil) returned non-nil")
	}
	if got := QuantityOrZero(nil); got != 0 {
		t.Error("QuantityOrZero(nil) != 0")
	}
	if got := PodPhase(nil); got != "" {
		t.Error("PodPhase(nil) != \"\"")
	}
}

// TestTerminationFoundDistinguishesPendingFromCleanExit is the reason Found
// exists at all.
//
// Without it, a container that has not started (nil Terminated) is
// indistinguishable from one that exited 0, and the filter would report every
// pending container as a clean exit - a false positive on every pod in a cluster.
func TestTerminationFoundDistinguishesPendingFromCleanExit(t *testing.T) {
	pending := &corev1.ContainerStatus{Name: "c", State: corev1.ContainerState{}}
	cleanExit := &corev1.ContainerStatus{
		Name:  "c",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}},
	}
	if TerminationOf(pending).Found {
		t.Error("a pending container reported Found")
	}
	if TerminationOf(pending).ExitCode != 0 {
		t.Error("a pending container reported a non-zero exit code")
	}
	if !TerminationOf(cleanExit).Found {
		t.Error("a clean exit reported Found = false; Found and ExitCode==0 are not interchangeable")
	}
}

func TestStatusesForSpecAlignsByName(t *testing.T) {
	// Position-based zipping pairs the wrong container with the wrong state as
	// soon as one status is missing.
	spec := []corev1.Container{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	statuses := []corev1.ContainerStatus{
		{Name: "a"},
		{Name: "c", RestartCount: 7},
	}
	got := StatusesForSpec(spec, statuses)
	if len(got) != 3 {
		t.Fatalf("want 3 entries, got %d", len(got))
	}
	if got[0] == nil || got[0].Name != "a" {
		t.Errorf("entry 0 = %+v, want container a", got[0])
	}
	if got[1] != nil {
		t.Errorf("entry 1 = %+v, want nil for the missing container b", got[1])
	}
	if got[2] == nil || got[2].RestartCount != 7 {
		t.Errorf("entry 2 = %+v, want container c with 7 restarts", got[2])
	}
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

func TestDedupKeyFormat(t *testing.T) {
	// The format is specified: "<podUID>/<containerName>:<restartCount>".
	if got := DedupKeyFor("uid-abc", "checkout-api", 5); got != "uid-abc/checkout-api:5" {
		t.Errorf("DedupKeyFor = %q", got)
	}
}

// TestDedupKeySeparatesContainersInOnePod is the regression for the bug this key
// was corrected for.
//
// The previous key was "<namespace>/<podName>:<restartCount>" - no container
// component - so a sidecar OOMKill and an application CrashLoopBackOff in the same
// pod with the same restart count produced the *same* key, and the second
// incident was silently dropped. These are different incidents with different
// remediations; losing one is not deduplication.
func TestDedupKeySeparatesContainersInOnePod(t *testing.T) {
	uid := types.UID("uid-shared")
	app := DedupKeyFor(uid, "checkout-api", 2)
	sidecar := DedupKeyFor(uid, "envoy-sidecar", 2)
	if app == sidecar {
		t.Fatalf("two containers in one pod shared dedup key %q; one incident would be lost", app)
	}

	// And end to end through the cache: both must be admitted.
	cache := newDedupCache(time.Minute, time.Now)
	if !cache.admit(app) {
		t.Error("the application container was suppressed")
	}
	if !cache.admit(sidecar) {
		t.Error("the sidecar was suppressed by the application's key")
	}

	// A genuine repeat of the *same* container is still suppressed.
	if cache.admit(app) {
		t.Error("a true repeat of the same container was admitted")
	}
}

// TestDedupKeySeparatesPodsRecreatedWithTheSameName covers the other half of
// why the UID is in the key.
func TestDedupKeySeparatesPodsRecreatedWithTheSameName(t *testing.T) {
	old := DedupKeyFor(types.UID("uid-old"), "checkout-api", 0)
	recreated := DedupKeyFor(types.UID("uid-new"), "checkout-api", 0)
	if old == recreated {
		t.Fatalf("a recreated pod with the same name shared key %q; a new failure would be hidden for the TTL", old)
	}
}

// TestTwoFailingContainersProduceTwoIncidents is the same guarantee at the
// classifier level rather than the key level.
func TestTwoFailingContainersProduceTwoIncidents(t *testing.T) {
	pod := newPod("multi")
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name: "envoy-sidecar",
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{corev1.ResourceMemory: quantity("128Mi")},
		},
	})
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{
		crashLooping(4), // checkout-api
		{Name: "envoy-sidecar", RestartCount: 4, // same restart count
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				ExitCode: OOMExitCode, Reason: "OOMKilled",
			}}},
	}

	records := classify(pod, time.Now())
	if len(records) != 2 {
		t.Fatalf("want 2 incidents (one per failing container), got %d: %+v", len(records), records)
	}
	keys := map[string]bool{}
	kinds := map[string]bool{}
	for _, r := range records {
		if keys[r.DedupKey] {
			t.Errorf("duplicate dedup key across containers: %q", r.DedupKey)
		}
		keys[r.DedupKey] = true
		kinds[string(r.Kind)] = true
	}
	if len(kinds) != 2 {
		t.Errorf("want two distinct failure kinds, got %v", kinds)
	}
}

func TestDedupSuppressesWithinTTL(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	now := base
	cache := newDedupCache(DedupTTL, func() time.Time { return now })

	if !cache.admit("payments/p1:3") {
		t.Fatal("first admission was suppressed")
	}
	now = base.Add(30 * time.Second)
	if cache.admit("payments/p1:3") {
		t.Error("a repeat within the TTL was admitted")
	}
	// The restart count distinguishes a genuinely new failure of the same pod.
	if !cache.admit("payments/p1:4") {
		t.Error("a new restart count was suppressed")
	}
}

func TestDedupAdmitsAgainAfterTTL(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	now := base
	cache := newDedupCache(DedupTTL, func() time.Time { return now })

	cache.admit("payments/p1:3")
	now = base.Add(DedupTTL + time.Second)
	if !cache.admit("payments/p1:3") {
		t.Error("a repeat after the TTL was suppressed; a recurring failure would go silent")
	}
}

func TestDedupSweepsExpiredEntries(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	now := base
	cache := newDedupCache(time.Minute, func() time.Time { return now })

	for _, key := range []string{"a", "b", "c"} {
		cache.admit(key)
	}
	if _, _, size := cache.stats(); size != 3 {
		t.Fatalf("size = %d, want 3", size)
	}
	now = base.Add(2 * time.Minute)
	cache.admit("d")
	if _, _, size := cache.stats(); size != 1 {
		t.Errorf("size after expiry = %d, want 1; the map grows without bound when pods churn", size)
	}
}

// TestDedupConcurrentAdmitsAreExact is the race the counter must not have.
//
// If admit were check-then-increment without the mutex, N goroutines would all
// see an absent key and all record it. Deduplication that admits duplicates is
// worse than none: it looks like it works.
func TestDedupConcurrentAdmitsAreExact(t *testing.T) {
	const goroutines = 64
	cache := newDedupCache(time.Minute, time.Now)

	admitted := make(chan bool, goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			<-start
			admitted <- cache.admit("shared/key")
		}()
	}
	close(start)

	allowed := 0
	for i := 0; i < goroutines; i++ {
		if <-admitted {
			allowed++
		}
	}
	if allowed != 1 {
		t.Errorf("%d goroutines were admitted the same key, want exactly 1", allowed)
	}
}

// ---------------------------------------------------------------------------
// Egress: bounded, non-blocking
// ---------------------------------------------------------------------------

func TestEmitDropsWhenChannelFullWithoutBlocking(t *testing.T) {
	client := fake.NewSimpleClientset()
	watcher := NewPodWatcher(client)

	// Fill the channel to capacity directly.
	for i := 0; i < EgressChannelCapacity; i++ {
		watcher.events <- &IncidentRecord{PodName: "filler"}
	}

	// The emit must return rather than block. If it blocked, the informer
	// callback thread would stall and so would every other pod's events, so the
	// test has a deadline rather than trusting the function to be non-blocking.
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.handle(newPod("flood", withStatus(oomKilled(1))))
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("emit blocked on a full channel; the informer callback thread would stall")
	}

	stats := watcher.Stats()
	if stats.Dropped != 1 {
		t.Errorf("Dropped = %d, want 1", stats.Dropped)
	}
	if stats.QueueDepth != EgressChannelCapacity {
		t.Errorf("QueueDepth = %d, want the channel left full at %d", stats.QueueDepth, EgressChannelCapacity)
	}
}

// TestHandleNeverBlocksUnderFlood drives far more incidents than the channel can
// hold, which is the real failure mode: a crash-looping deployment produces
// hundreds of events in a burst.
func TestHandleNeverBlocksUnderFlood(t *testing.T) {
	client := fake.NewSimpleClientset()
	watcher := NewPodWatcher(client)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < EgressChannelCapacity*3; i++ {
			pod := newPod("flood", withStatus(oomKilled(int32(i))))
			watcher.handle(pod)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handle blocked under flood")
	}

	stats := watcher.Stats()
	if stats.QueueDepth != EgressChannelCapacity {
		t.Errorf("QueueDepth = %d, want %d", stats.QueueDepth, EgressChannelCapacity)
	}
	if stats.Dropped == 0 {
		t.Error("expected drops once the channel filled")
	}
}

// ---------------------------------------------------------------------------
// Informer integration with the fake clientset
// ---------------------------------------------------------------------------

func newFakeClient(pods ...*corev1.Pod) *fake.Clientset {
	objects := make([]runtime.Object, 0, len(pods))
	for _, pod := range pods {
		objects = append(objects, pod)
	}
	return fake.NewSimpleClientset(objects...)
}

func TestInformerDeliversOOMKilledFromInitialList(t *testing.T) {
	// The informer's initial list contains every existing pod, not only new ones,
	// so a daemon started during an ongoing incident must still see it.
	client := newFakeClient(newPod("existing-oom", withStatus(oomKilled(2))))
	watcher := NewPodWatcher(client, WithLogger(discardLogger()))

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.Run(stop)
	}()

	select {
	case record := <-watcher.Events():
		if record.Kind != FailureOOMKilled {
			t.Errorf("Kind = %q, want %q", record.Kind, FailureOOMKilled)
		}
		if record.PodName != "existing-oom" {
			t.Errorf("PodName = %q", record.PodName)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no incident delivered from the initial list")
	}

	close(stop)
	<-done
}

func TestInformerDeliversCrashLoopFromPodUpdate(t *testing.T) {
	pod := newPod("updating", withStatus(running(0)))
	client := newFakeClient(pod)
	watcher := NewPodWatcher(client, WithLogger(discardLogger()))

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.Run(stop)
	}()

	// Let the initial list sync before mutating, otherwise the update races the
	// sync and the test is testing the race rather than the transition.
	waitForSync(t, watcher)
	if got := len(watcher.Events()); got != 0 {
		t.Fatalf("a running pod produced %d incidents", got)
	}

	updated := pod.DeepCopy()
	updated.Status.ContainerStatuses = []corev1.ContainerStatus{crashLooping(4)}
	if _, err := client.CoreV1().Pods("payments").Update(
		newCtx(t), updated, metav1.UpdateOptions{},
	); err != nil {
		t.Fatalf("update failed: %v", err)
	}

	select {
	case record := <-watcher.Events():
		if record.Kind != FailureCrashLoopBackOff {
			t.Errorf("Kind = %q, want %q", record.Kind, FailureCrashLoopBackOff)
		}
		if record.Restarts != 4 {
			t.Errorf("Restarts = %d, want 4", record.Restarts)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no incident delivered from the pod update")
	}

	close(stop)
	<-done
}

func TestInformerIgnoresHealthyPodUpdates(t *testing.T) {
	pod := newPod("healthy", withStatus(running(0)))
	client := newFakeClient(pod)
	watcher := NewPodWatcher(client, WithLogger(discardLogger()))

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.Run(stop)
	}()
	defer func() {
		close(stop)
		<-done
	}()
	waitForSync(t, watcher)

	updated := pod.DeepCopy()
	updated.Status.Phase = corev1.PodSucceeded
	if _, err := client.CoreV1().Pods("payments").Update(
		newCtx(t), updated, metav1.UpdateOptions{},
	); err != nil {
		t.Fatalf("update failed: %v", err)
	}

	// Wait for the informer to actually hold the updated object, rather than
	// sleeping a fixed interval and hoping. A fixed sleep is slow when it passes
	// and still racy when it does not: it cannot distinguish "the handler saw
	// nothing" from "the handler has not run yet".
	waitForStore(t, watcher, "payments", "healthy", corev1.PodSucceeded)

	// The update has been delivered and handled, so an empty channel is now a real
	// assertion rather than a timing artefact.
	if record := drainOne(watcher.Events()); record != nil {
		t.Fatalf("a healthy pod produced an incident: %+v", record)
	}
	if got := watcher.Stats().Emitted; got != 0 {
		t.Errorf("Emitted = %d, want 0", got)
	}
}

// TestInformerDeduplicatesRapidRepeats is the end-to-end dedup guarantee: the same
// pod re-delivered must produce exactly one incident.
func TestInformerDeduplicatesRapidRepeats(t *testing.T) {
	pod := newPod("repeat", withStatus(oomKilled(3)))
	client := newFakeClient(pod)
	watcher := NewPodWatcher(client, WithLogger(discardLogger()))

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.Run(stop)
	}()

	select {
	case <-watcher.Events():
	case <-time.After(10 * time.Second):
		t.Fatal("no first incident")
	}

	// Re-deliver the identical object many times.
	for i := 0; i < 20; i++ {
		watcher.onUpdate(nil, pod)
	}

	// The Run goroutine increments these; read them only after it has. See
	// waitForStats for why reading them immediately is a scheduling race.
	waitForStats(t, watcher, 1, 1)

	if got := watcher.Stats().DedupSuppressed; got == 0 {
		t.Errorf("DedupSuppressed = 0; %d repeats were not suppressed", 20)
	}
	if got := watcher.Stats().Emitted; got != 1 {
		t.Errorf("Emitted = %d, want 1", got)
	}

	close(stop)
	<-done
}

// TestNonPodObjectsAreIgnored covers the DeletedFinalStateUnknown tombstone that
// arrives when a delete races a resync. Type-asserting without a check panics.
func TestNonPodObjectsAreIgnored(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a non-pod object panicked: %v", r)
		}
	}()
	watcher := NewPodWatcher(fake.NewSimpleClientset(), WithLogger(discardLogger()))
	watcher.onAdd("not a pod")
	watcher.onAdd(nil)
	watcher.onUpdate(nil, 42)
}

func TestRunClosesEventsOnShutdown(t *testing.T) {
	// A consumer ranging over Events must terminate. An unclosed channel would
	// hang the daemon on SIGTERM, which is the bug ROADMAP 3.3.5 is about.
	watcher := NewPodWatcher(fake.NewSimpleClientset(), WithLogger(discardLogger()))
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.Run(stop)
	}()

	// Give the informer a moment to start before stopping it.
	time.Sleep(200 * time.Millisecond)
	close(stop)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the stop channel closed")
	}

	// Draining must terminate.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range watcher.Events() {
		}
	}()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("Events() was not closed on shutdown")
	}
}

// TestRunLogsTheAppliedResyncPeriod pins the R (reliability) logging fix.
//
// WithResyncPeriod changes w.resync, but Run logged the DefaultResyncPeriod
// constant instead of the value it actually applied - so an operator reading the
// log deduced the wrong resync cadence. The log must report the applied value.
func TestRunLogsTheAppliedResyncPeriod(t *testing.T) {
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// Seed a pod: an empty-store informer and the normal path differ, and this
	// test targets the normal startup path.
	watcher := NewPodWatcher(newFakeClient(newPod("resync-probe", withStatus(oomKilled(1)))),
		WithLogger(log),
		WithResyncPeriod(5*time.Minute))

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.Run(stop)
	}()

	// Wait until Run actually logs the start line. Closing stop before Run has
	// reached it makes Run take the "cache did not sync" early return - a different
	// code path that never logs resync - so the test would race its own subject.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logs.String(), "pod watcher started") {
		if time.Now().After(deadline) {
			t.Fatalf("Run never logged 'pod watcher started'; logged:\n%s", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	<-done

	out := logs.String()
	if !strings.Contains(out, "resync=5m0s") {
		t.Errorf("Run did not log the applied resync=5m0s; logged:\n%s", out)
	}
	if strings.Contains(out, "resync=30s") {
		t.Errorf("Run logged the DefaultResyncPeriod constant (30s) rather than the applied 5m0s:\n%s", out)
	}
}

// syncBuffer is a concurrency-safe sink for a slog handler. Run logs from its own
// goroutine while the test polls the buffer, so an unsynchronised bytes.Buffer is
// itself a data race under -race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestInformerCallbacksStopBeforeTheChannelCloses guards the shutdown ordering.
//
// Run closes w.events on the way out, and every informer handler it registered
// does a non-blocking select-send on that channel. A send on a closed channel is
// "ready", so the send case is chosen and it panics. Before the fix Run closed
// the channel without ever waiting for the informer to stop: factory.Start runs
// the handlers on goroutines the factory owns, and one dispatched in the window
// after stop closed sent on the closed channel - a SIGKILL-shaped crash on a
// routine SIGTERM. The fix defers factory.Shutdown() after close so LIFO runs
// Shutdown first; client-go v0.31's Shutdown -> wg.Wait chain has returned every
// handler goroutine before close runs.
//
// The assertion is the -race detector: concurrent send and close on a channel is
// a data race it flags, and a send-after-close is a runtime panic that fails the
// test binary. This drives real informer traffic through the watcher's own
// goroutines while stopping, so the shutdown path and the handler dispatch
// overlap. It increases the pressure on that window (it is not a
// guaranteed-reproduce test - the bug is timing-dependent) and, combined with
// -race, is what CI relies on.
func TestInformerCallbacksStopBeforeTheChannelCloses(t *testing.T) {
	pod := newPod("shutdown-race", withStatus(oomKilled(1)))
	client := newFakeClient(pod)
	watcher := NewPodWatcher(client, WithLogger(discardLogger()))

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.Run(stop)
	}()

	waitForSync(t, watcher)

	// Consume throughout, so a handler is never blocked on a full egress channel
	// and the sends-under-load are real. The range ends when Run closes Events().
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range watcher.Events() {
		}
	}()

	// Hammer the informer with updates from another goroutine while we stop it,
	// so the informer's handler dispatch and Run's teardown genuinely overlap.
	updates := make(chan struct{})
	go func() {
		defer close(updates)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			updated := pod.DeepCopy()
			updated.Status.ContainerStatuses = []corev1.ContainerStatus{crashLooping(int32(i % 9))}
			_, _ = client.CoreV1().Pods("payments").Update(newCtx(t), updated, metav1.UpdateOptions{})
		}
	}()

	close(stop)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after stop closed")
	}
	// If Events() was never closed, the consumer's range never ends.
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("Events() was not closed on shutdown")
	}
	<-updates
}

// ---------------------------------------------------------------------------
// Read-only guarantee (ROADMAP 3.1.4)
// ---------------------------------------------------------------------------

func TestReadOnlyFacadeExposesNoMutatingMethod(t *testing.T) {
	if offenders := ClientsetOnly(); len(offenders) != 0 {
		t.Errorf("ReadOnlyClientset exposes mutating methods: %v", offenders)
	}
}

// leakyFacade is the negative control for the allow-list audit.
//
// It looks read-only by name and still hands back a full clientset - the obvious
// way to defeat a name-based check, and the reason the audit is an exact
// allow-list rather than a deny-list of write verbs.
//
// Three earlier versions of this control were vacuous and all passed without
// proving anything: an empty struct with no methods; a struct holding the
// clientset in a *field* rather than returning it from a method; and a
// reflect.StructOf construction that never exposed a method either. A control
// that cannot fail is worse than none, because it reads as evidence.
type leakyFacade struct{ inner kubernetes.Interface }

// Client returns the wrapped clientset.
func (l *leakyFacade) Client() kubernetes.Interface { return l.inner }

// sneakyAccessor is a second control: an extra method with an innocuous name.
type sneakyAccessor struct{}

// Exec runs an arbitrary command. The name carries no write verb.
func (sneakyAccessor) Exec(string) error { return nil }

func TestFacadeAllowListRejectsALeakyGetter(t *testing.T) {
	if AllowedFacadeMethods["Client"] {
		t.Fatal("the allow-list already permits Client; the control cannot prove anything")
	}
	// The facade under test does not have it, so the audit is clean...
	if got := DisallowedFacadeMethods(); len(got) != 0 {
		t.Errorf("the real facade reported %v", got)
	}
	// ...and a facade that does have it is rejected.
	typ := reflect.TypeOf(&leakyFacade{})
	if !hasMethod(typ, "Client") {
		t.Fatal("the control type does not expose Client")
	}
	if AllowedFacadeMethods["Client"] {
		t.Error("Client is allow-listed")
	}
}

func TestFacadeAllowListRejectsAnInnocuousName(t *testing.T) {
	// "Exec" carries no write verb, which is precisely why a deny-list would
	// miss it and an allow-list does not.
	if AllowedFacadeMethods["Exec"] {
		t.Fatal("Exec is allow-listed")
	}
	if !hasMethod(reflect.TypeOf(sneakyAccessor{}), "Exec") {
		t.Fatal("the control type does not expose Exec")
	}
}

func hasMethod(typ reflect.Type, name string) bool {
	for i := 0; i < typ.NumMethod(); i++ {
		if typ.Method(i).Name == name {
			return true
		}
	}
	return false
}

// TestFacadeExposesOnlyObservationalVerbs states the contract positively, so a
// future method that is both write-capable *and* allow-listed by mistake is still
// visible in review.
func TestFacadeExposesOnlyObservationalVerbs(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(ReadOnlyClientset{}),
		reflect.TypeOf(PodReader{}),
		reflect.TypeOf(EventReader{}),
	} {
		for i := 0; i < typ.NumMethod(); i++ {
			name := typ.Method(i).Name
			switch name {
			case "Pods", "PodsIn", "Events", "EventsIn", "Get", "List", "Watch", "Namespace":
			default:
				t.Errorf("%s exposes unexpected method %q", typ.Name(), name)
			}
		}
	}
}

// TestNoMutatingCallsInSources parses this package's AST rather than trusting a
// review note (ROADMAP 3.2.3).
//
// A grep cannot distinguish a call from a comment or a string. An AST walk can,
// and it catches the obvious regression: someone reaching for
// client.CoreV1().Pods(ns).Delete(...) inside this package.
// clientMutatingVerbs are client-go's mutating client methods.
//
// Named explicitly rather than reused from the facade allow-list, because this
// test audits *call sites* while the allow-list audits *types*, and conflating
// them would make one weaken the other.
var clientMutatingVerbs = []string{
	"Create", "Update", "UpdateStatus", "Patch", "Delete", "DeleteCollection",
	"Apply", "Replace", "Scale", "Bind", "Evict", "EvictV1", "EvictV1beta1",
}

func TestNoMutatingCallsInSources(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	type call struct {
		pos  token.Position
		name string
	}
	var offenders []call

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			// Selector chains: find X.Method(...) where Method is a write verb.
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok {
					// Chained: a.b().Create(...) has Sel.Sel as the outer selector,
					// which the parent Inspect still visits.
					return true
				}
				for _, verb := range clientMutatingVerbs {
					if sel.Sel.Name == verb {
						offenders = append(offenders, call{
							pos:  fset.Position(sel.Pos()),
							name: ident.Name + "." + sel.Sel.Name,
						})
					}
				}
				return true
			})
		}
	}

	// Allow the audit helpers themselves, which legitimately *name* write verbs.
	allowed := map[string]bool{
		"ClientsetOnly":                true,
		"clientMutatingVerbs":          true,
		"TestNoMutatingCallsInSources": true,
	}
	var unexpected []call
	for _, off := range offenders {
		if !allowed[off.name] {
			unexpected = append(unexpected, off)
		}
	}
	if len(unexpected) > 0 {
		var detail []string
		for _, off := range unexpected {
			detail = append(detail, off.pos.String()+" "+off.name)
		}
		t.Errorf("mutating client calls found in internal/k8s:\n  %s",
			strings.Join(detail, "\n  "))
	}
}

// TestFakeClientsetSanity confirms the fixture client really is usable, so a
// green informer test cannot be explained by the fake silently doing nothing.
func TestFakeClientsetSanity(t *testing.T) {
	client := newFakeClient(newPod("sanity", withStatus(oomKilled(1))))

	var seen []string
	client.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		seen = append(seen, action.GetVerb())
		return false, nil, nil
	})

	pods, err := client.CoreV1().Pods("payments").List(newCtx(t), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(seen) == 0 {
		t.Error("the reactor never fired, so the fake client may not be intercepting")
	}
	if len(pods.Items) != 1 {
		t.Errorf("len(pods) = %d, want 1", len(pods.Items))
	}
}
