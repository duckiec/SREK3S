package k8s

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// TestANonOOMTerminationIsDroppedBeforeDedup pins the defect found by the E2E
// detonation, and it is the reason this test exists at all: nothing covered the
// behaviour, so a crash-looping container was detected and then never reported.
//
// The dedup key is `<podUID>/<containerName>:<restartCount>` and does not include
// the kind. A crash-looping container therefore produces, for the same restart
// count:
//
//  1. a transient Terminated{exit 1}  -> key "uid/app:2"
//  2. Waiting{CrashLoopBackOff}        -> key "uid/app:2" as well
//
// The transient state wins the key, and the state that actually carries the
// evidence is suppressed as a duplicate. On the E2E run the Sentinel logged five
// `dispatch failed` lines for the crashloop pod, every one of them
// `kind: Terminated ... failure kind has no wire representation` - and not one
// CrashLoopBackOff, because the Terminated record had already taken the key.
//
// The filter fixes both halves at once: the un-serialisable state is never built,
// so it never claims the key, and the symptom behind it is free to be admitted.
func TestANonOOMTerminationIsDroppedBeforeDedup(t *testing.T) {
	// Stage 1: the container has just exited non-zero, not an OOM.
	terminated := newPod("app-pod", func(p *corev1.Pod) {
		p.UID = "crash-uid"
	})
	terminated.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:         "checkout-api",
		RestartCount: 2,
		State: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				ExitCode: 1,
				Reason:   "Error",
			},
		},
	}}

	records := classify(terminated, time.Now())
	if len(records) != 0 {
		t.Fatalf("a non-OOM exit produced %d record(s): %+v; Contract A has no "+
			"enum member for it, so it can never reach the wire", len(records), records)
	}

	// Stage 2: the same container, same restart count, now in backoff. This is
	// the state that carries the evidence.
	backoff := newPod("app-pod", func(p *corev1.Pod) {
		p.UID = "crash-uid"
	})
	backoff.Status.ContainerStatuses = []corev1.ContainerStatus{crashLooping(2)}

	records = classify(backoff, time.Now())
	if len(records) != 1 {
		t.Fatalf("want 1 record for the backoff, got %d: %+v", len(records), records)
	}
	if records[0].Kind != FailureCrashLoopBackOff {
		t.Errorf("kind = %q, want %q", records[0].Kind, FailureCrashLoopBackOff)
	}

	// Stage 3: the whole point. The key the Terminated state would have claimed
	// must still be free, so the CrashLoopBackOff record is not suppressed as a
	// duplicate. Reintroducing the filter's absence would fail exactly here.
	cache := newDedupCache(time.Minute, time.Now)
	if !cache.admit(records[0].DedupKey) {
		t.Errorf("the CrashLoopBackOff key %q was already claimed by an earlier "+
			"state, so the evidence is suppressed as a duplicate",
			records[0].DedupKey)
	}
}

// TestTheDedupKeyIsWhatWouldHaveCollided names the mechanism rather than leaving
// it implicit in the test above.
//
// If the key ever grows a kind component, the two states stop colliding and the
// filter above becomes unnecessary - which is a legitimate change, but it should
// be a decision rather than a side effect. This test fails if someone "fixes"
// the key without noticing the filter is then redundant.
func TestTheDedupKeyIsWhatWouldHaveCollided(t *testing.T) {
	terminated := &corev1.ContainerStatus{
		Name:         "checkout-api",
		RestartCount: 2,
		State: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error"},
		},
	}
	backoff := &corev1.ContainerStatus{
		Name:         "checkout-api",
		RestartCount: 2,
		State: corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{Reason: string(FailureCrashLoopBackOff)},
		},
	}
	terminatedKey := DedupKeyFor("uid", "checkout-api", terminated.RestartCount)
	backoffKey := DedupKeyFor("uid", "checkout-api", backoff.RestartCount)
	if terminatedKey != backoffKey {
		t.Fatalf("the two states no longer collide (%q vs %q); the dedup key "+
			"changed, so re-examine whether the non-OOM filter is still the right fix",
			terminatedKey, backoffKey)
	}
}

// TestOOMTerminationsAreStillReported is the negative control for the filter
// above, in the direction that matters most.
//
// A filter that dropped everything would satisfy every other test here, because
// they all assert on the absence of records. This one asserts the OOM path is
// untouched: a 137 must still produce exactly one OOMKilled record, because that
// is the record that unlocks the Tier-1 memory-limit diff.
func TestOOMTerminationsAreStillReported(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pod   *corev1.Pod
		kind  FailureKind
		label string
	}{
		{
			name: "exit 137",
			pod: func() *corev1.Pod {
				p := newPod("oom-pod", func(p *corev1.Pod) { p.UID = "oom-uid" })
				p.Status.ContainerStatuses = []corev1.ContainerStatus{oomKilled(3)}
				return p
			}(),
			kind:  FailureOOMKilled,
			label: "an OOM exit must still be reported",
		},
		{
			name: "OOMKilled reason at another exit code",
			pod: func() *corev1.Pod {
				p := newPod("reason-pod", func(p *corev1.Pod) { p.UID = "reason-uid" })
				p.Status.ContainerStatuses = []corev1.ContainerStatus{{
					Name: "checkout-api", RestartCount: 1,
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: 2, Reason: "OOMKilled",
						},
					},
				}}
				return p
			}(),
			kind:  FailureOOMKilled,
			label: "the reason alone is enough; the exit code need not be 137",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := classify(tc.pod, time.Now())
			if len(records) != 1 {
				t.Fatalf("%s: want 1 record, got %d: %+v", tc.label, len(records), records)
			}
			if records[0].Kind != tc.kind {
				t.Errorf("%s: kind = %q, want %q", tc.label, records[0].Kind, tc.kind)
			}
		})
	}
}

// TestASidecarOOMStillReportsWithACrashLoopingApplication guards the multi-
// container case the earlier dedup work covered: filtering non-OOM terminations
// must not cost the sidecar its own OOM record.
func TestASidecarOOMStillReportsWithACrashLoopingApplication(t *testing.T) {
	pod := newPod("mixed-pod", func(p *corev1.Pod) { p.UID = "mixed-uid" })
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "envoy-sidecar"})
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{
		crashLooping(4),
		{Name: "envoy-sidecar", RestartCount: 4,
			State: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					ExitCode: OOMExitCode, Reason: "OOMKilled",
				},
			}},
	}
	records := classify(pod, time.Now())
	if len(records) != 2 {
		t.Fatalf("want 2 records (one per failing container), got %d: %+v", len(records), records)
	}
	kinds := map[FailureKind]int{}
	for _, r := range records {
		kinds[r.Kind]++
	}
	if kinds[FailureOOMKilled] != 1 || kinds[FailureCrashLoopBackOff] != 1 {
		t.Errorf("kinds = %v, want one OOMKilled and one CrashLoopBackOff", kinds)
	}
}
