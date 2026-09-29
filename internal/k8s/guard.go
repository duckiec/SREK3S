package k8s

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// Nil-safe accessors for the deeply nested pointer trees in a Pod object.
//
// AGENTS.md §3.1 requires an explicit nil check at *every* preceding level, not
// just the first hop. Kubernetes API objects make that easy to get wrong:
//
//	pod.Status.ContainerStatuses[0].State.Terminated.ExitCode
//
// is four dereferences and two index operations, any of which can be nil. A pod
// that is Pending has a ContainerStatus with a nil State; a container that is
// being created has a State with a nil Terminated and a nil Waiting; a pod whose
// spec has no limits has a nil Resources. Every one of those is normal, not
// malformed, and the watcher sees all of them during normal operation.
//
// Every accessor here returns a zero value instead of panicking. That is what
// makes the callers total: a filter can ask "is this terminated?" about a
// container that has not started without a guard at the call site.
//
// ROADMAP 3.2.3 forbids raw chained access outside this file. The reasoning: an
// accessor per field is auditable, and the alternative is a five-deep expression
// in a filter callback where the fourth nil check is easy to omit and impossible
// to notice in review.

// Termination describes a container that has exited. Mirrors
// corev1.ContainerStateTerminated, flattened so callers need no pointer chasing.
type Termination struct {
	ExitCode   int32
	Reason     string
	Message    string
	Signal     int32
	StartedAt  int64
	FinishedAt int64
	// Found reports whether a Terminated state was actually present, as opposed
	// to every field being zero because the container has not exited.
	//
	// This is not a convenience. A container that has not started has a nil
	// Terminated, and "ExitCode == 0" is true for a nil Terminated. Without
	// Found, "is this a clean exit?" and "has this started?" are
	// indistinguishable, and the filter would treat every pending container as a
	// clean exit - which is a false positive on every pod in a cluster.
	Found bool
}

// Waiting describes a container that is waiting to start.
type Waiting struct {
	Reason  string
	Message string
	Found   bool
}

// ResourceLimits returns a pod container's limits, or a nil map when unset.
//
// A nil map reads as empty in Go, so callers can range over the result without a
// guard. Returning a non-nil empty map would hide the difference between "no
// limits declared" and "limits declared as empty", and only the first is a
// finding worth escalating.
func ResourceLimits(limits corev1.ResourceList) corev1.ResourceList {
	return limits
}

// MemoryLimitBytes returns the memory limit in bytes, and whether one was set.
func MemoryLimitBytes(limits corev1.ResourceList) (int64, bool) {
	if limits == nil {
		return 0, false
	}
	// resource.Quantity is a struct value, not a pointer, so the `ok` from the
	// map lookup is the only existence test available. A nil check here would not
	// compile, which is a useful reminder that the map lookup is the guard.
	quantity, ok := limits[corev1.ResourceMemory]
	if !ok {
		return 0, false
	}
	value, ok := quantity.AsInt64()
	if !ok {
		// A fractional or very large quantity is legal YAML and cannot be
		// expressed as int64. Reporting "not set" would be a lie, so this returns
		// false and the caller treats the limit as unknown, which fails closed.
		return 0, false
	}
	return value, true
}

// MemoryRequestBytes returns the memory request in bytes, and whether one was set.
func MemoryRequestBytes(requests corev1.ResourceList) (int64, bool) {
	return MemoryLimitBytes(requests)
}

// TerminationOf returns the container's terminated state, nil-safe at every level.
//
// The chain is: the caller has already resolved a non-nil ContainerStatus;
// ContainerStatus.State is a struct, not a pointer, so it needs no check;
// State.Terminated is a pointer and is the one that matters.
func TerminationOf(status *corev1.ContainerStatus) Termination {
	if status == nil {
		return Termination{}
	}
	terminated := status.State.Terminated
	if terminated == nil {
		return Termination{}
	}
	return Termination{
		ExitCode:   terminated.ExitCode,
		Reason:     terminated.Reason,
		Message:    terminated.Message,
		Signal:     terminated.Signal,
		StartedAt:  terminated.StartedAt.Unix(),
		FinishedAt: terminated.FinishedAt.Unix(),
		Found:      true,
	}
}

// WaitingOf returns the container's waiting state, nil-safe at every level.
func WaitingOf(status *corev1.ContainerStatus) Waiting {
	if status == nil {
		return Waiting{}
	}
	waiting := status.State.Waiting
	if waiting == nil {
		return Waiting{}
	}
	return Waiting{
		Reason:  waiting.Reason,
		Message: waiting.Message,
		Found:   true,
	}
}

// RunningOf reports whether the container is currently running.
//
// `Running != nil` is the only safe test: ContainerState.Running is a pointer,
// and a container can have Running, Waiting and Terminated all nil during a
// transition. Comparing a struct field directly would be a compile error, which
// is the one failure mode Go catches for us.
func RunningOf(status *corev1.ContainerStatus) bool {
	if status == nil {
		return false
	}
	return status.State.Running != nil
}

// LastTerminationOf returns the previous termination, nil-safe at every level.
//
// LastTerminationState is nil for a container that has never exited, which is
// every container's first start. Reading it unguarded is the most common panic in
// this shape.
func LastTerminationOf(status *corev1.ContainerStatus) Termination {
	if status == nil {
		return Termination{}
	}
	last := status.LastTerminationState.Terminated
	if last == nil {
		return Termination{}
	}
	return Termination{
		ExitCode:   last.ExitCode,
		Reason:     last.Reason,
		Message:    last.Message,
		Signal:     last.Signal,
		StartedAt:  last.StartedAt.Unix(),
		FinishedAt: last.FinishedAt.Unix(),
		Found:      true,
	}
}

// RestartCount returns the restart count, and 0 for a nil status.
func RestartCount(status *corev1.ContainerStatus) int32 {
	if status == nil {
		return 0
	}
	return status.RestartCount
}

// StatusForContainer finds a container status by name, nil-safe at every level.
//
// Returns nil when the container has no status entry, which happens between the
// spec being admitted and the kubelet reporting the first status. Callers get a
// nil and must cope; that is why every other accessor here takes a nil.
func StatusForContainer(statuses []corev1.ContainerStatus, name string) *corev1.ContainerStatus {
	for i := range statuses {
		if statuses[i].Name == name {
			return &statuses[i]
		}
	}
	return nil
}

// StatusesForSpec returns the statuses indexed by the spec's container order,
// with a nil entry for any container that has no status yet.
//
// Index alignment matters: a caller that zips spec containers against statuses by
// position pairs the wrong container with the wrong state as soon as one is
// missing, which produces a confident, wrong classification.
func StatusesForSpec(
	specContainers []corev1.Container,
	statuses []corev1.ContainerStatus,
) []*corev1.ContainerStatus {
	out := make([]*corev1.ContainerStatus, len(specContainers))
	for i := range specContainers {
		out[i] = StatusForContainer(statuses, specContainers[i].Name)
	}
	return out
}

// PodPhase returns the pod phase, tolerating a nil pod.
func PodPhase(pod *corev1.Pod) corev1.PodPhase {
	if pod == nil {
		return ""
	}
	return pod.Status.Phase
}

// QuantityOrZero returns a quantity's integer value, and 0 when absent or
// unrepresentable.
func QuantityOrZero(quantity *resource.Quantity) int64 {
	if quantity == nil {
		return 0
	}
	value, ok := quantity.AsInt64()
	if !ok {
		return 0
	}
	return value
}

// MemoryLimitForContainer resolves a container's memory limit from the pod spec,
// nil-safe at every level: nil pod, nil spec, missing container, nil Resources,
// missing or non-integral memory.
func MemoryLimitForContainer(pod *corev1.Pod, containerName string) (int64, bool) {
	if pod == nil {
		return 0, false
	}
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name != containerName {
			continue
		}
		return MemoryLimitBytes(pod.Spec.Containers[i].Resources.Limits)
	}
	return 0, false
}
