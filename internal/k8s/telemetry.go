package k8s

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Telemetry bounds. These are contract values, not tuning knobs.
const (
	// LogTailLines caps how many trailing lines are fetched per container.
	//
	// An RCA reasons over the tail - the failure signature is at the end - so a
	// bounded tail is both sufficient and predictable. Fetching whole logs for a
	// container that has been spewing since boot would spend the detection budget
	// on text nobody reads.
	LogTailLines int64 = 100

	// LogLimitBytes caps the response body at 50 KiB.
	//
	// The second bound, and the one that matters more: TailLines bounds *lines*,
	// and a single log line can be megabytes of a serialised request dump. Only a
	// byte bound makes the memory cost of an incident provable, which is what keeps
	// this inside the 2s detection budget (ARCH §7).
	LogLimitBytes int64 = 51200

	// ClusterEventsMax caps how many events are fetched per incident.
	//
	// This is a cross-language contract value, not a tuning knob. The agent's
	// IncidentPayload.cluster_events is Field(max_length=CLUSTER_EVENTS_MAX=64)
	// (agent/models.py), and that bound is a hard reject: a payload carrying more
	// than 64 events is refused 422 and the incident is escalated. Before this
	// bound the List had no Limit, so a pod with a long event history - a
	// crash-loop that has been crashing for days - produced hundreds of events,
	// and the incident the Sentinel worked hardest to build was discarded by the
	// agent as invalid.
	//
	// Kept in sync with the agent by cmd/sentinel's TestClusterEventsMaxMatchesAgent
	// and the agent's own test_phase4_regressions. If either side changes, change both.
	ClusterEventsMax int64 = 64

	// TelemetryTimeout bounds each network call independently.
	//
	// Strictly bounded per call, not per incident: a slow log fetch must not eat
	// the entire budget of the event fetch that follows it, and neither must hang
	// the worker forever on a wedged apiserver (AGENTS.md §3.2).
	TelemetryTimeout = 3 * time.Second
)

// Telemetry fetches the raw evidence for one incident.
//
// Both methods return *unscrubbed* text. Scrubbing is the caller's job and
// happens in memory in the worker, before anything is serialised
// (ROADMAP 3.4.2) - which is only possible while the text is still in memory.
// Returning a scrubbed copy from here would put a second, easily-skipped
// scrubber in the path of anyone who adds a caller later.
type Telemetry struct {
	client kubernetes.Interface
	// logReader is overridable in tests; nil means use the real API.
	logReader func(namespace, pod, container string, opts *corev1.PodLogOptions) (string, error)
}

// NewTelemetry builds a telemetry fetcher over a clientset.
func NewTelemetry(client kubernetes.Interface) *Telemetry {
	return &Telemetry{client: client}
}

// FieldSelectorEventUID builds the selector that joins events to a pod.
//
// Uses the pod UID rather than name, matching the dedup key. A name-based selector
// picks up events from a *previous* pod with the same name, which produces an
// RCA that confidently attributes an old failure to a new pod.
func FieldSelectorEventUID(podUID string) string {
	return fmt.Sprintf("involvedObject.uid=%s", podUID)
}

// Logs fetches the container's log tail.
//
// previous selects the *previous* container instance, and it is correct to set it
// for both incident shapes this watcher emits:
//
//   - Terminated (OOMKilled): the container that died is the current instance, but
//     kubelet has usually already replaced it, and reading the replacement returns
//     a blank or freshly-booted log that contains no failure at all.
//   - Waiting (CrashLoopBackOff): the current instance is the one kubelet keeps
//     failing to start, which is blank by construction. The interesting log is the
//     previous instance's.
//
// So `previous` is derived from "is the container currently running" rather than
// taken from the caller, because a caller passing it wrong gets a blank log and
// no error - the worst possible failure mode for evidence collection.
func (t *Telemetry) Logs(ctx context.Context, namespace, podName, containerName string, previous bool) (string, error) {
	// PodLogOptions takes *int64 for both bounds, and nil there means
	// "unbounded" - which is exactly why the fields are pointers. Setting either to
	// nil would silently drop the cap these constants exist to enforce, so the
	// values are bound to named locals and addressed explicitly.
	tailLines := LogTailLines
	limitBytes := LogLimitBytes
	opts := &corev1.PodLogOptions{
		Container:  containerName,
		TailLines:  &tailLines,
		LimitBytes: &limitBytes,
		Previous:   previous,
	}

	if t.logReader != nil {
		// Redacted on the way out, exactly as the real path is. An earlier version
		// returned the reader's error untouched, so the injectable seam - the one
		// tests use - silently skipped redaction while the production path enforced
		// it. A test seam with weaker guarantees than the code it stands in for is
		// worse than no seam: it makes the tests unable to catch the regression they
		// exist to catch.
		text, err := t.logReader(namespace, podName, containerName, opts)
		if err != nil {
			return "", fmt.Errorf(
				"telemetry: fetching logs for %s/%s: %s",
				namespace, podName, RedactError(err),
			)
		}
		return text, nil
	}

	if t.client == nil {
		return "", fmt.Errorf("telemetry: no client configured")
	}

	// Strict per-call bound, applied to a derived context so the caller's own
	// deadline still wins if it is shorter.
	callCtx, cancel := context.WithTimeout(ctx, TelemetryTimeout)
	defer cancel()

	stream, err := t.client.CoreV1().
		Pods(namespace).
		GetLogs(podName, opts).
		Stream(callCtx)
	if err != nil {
		return "", fmt.Errorf("telemetry: fetching logs for %s/%s: %s", namespace, podName, RedactError(err))
	}
	defer func() {
		// Drain and close. A stream left open holds a connection and, on the
		// apiserver, a pod's log handle.
		_, _ = io.Copy(io.Discard, stream)
		_ = stream.Close()
	}()

	var builder strings.Builder
	// LimitBytes is already enforced server-side, but the response is bounded again
	// here because a server is not obliged to honour it and an unbounded read is an
	// unbounded allocation.
	//nolint:gosec // LimitBytes is the configured bound being enforced.
	_, err = io.Copy(&boundedWriter{w: &builder, remaining: LogLimitBytes}, stream)
	if err != nil {
		return "", fmt.Errorf("telemetry: reading logs for %s/%s: %s", namespace, podName, RedactError(err))
	}
	return builder.String(), nil
}

// Events fetches the events joined to this pod.
//
// An empty pod UID yields no events rather than an error: a pod that has been
// deleted between the watch event and this call has no events to find, and failing
// the whole incident over that would lose the logs we already have.
func (t *Telemetry) Events(ctx context.Context, namespace, podUID string) ([]corev1.Event, error) {
	if t.client == nil {
		return nil, fmt.Errorf("telemetry: no client configured")
	}
	if podUID == "" {
		return nil, nil
	}

	callCtx, cancel := context.WithTimeout(ctx, TelemetryTimeout)
	defer cancel()

	list, err := t.client.CoreV1().
		Events(namespace).
		List(callCtx, metav1.ListOptions{
			FieldSelector: FieldSelectorEventUID(podUID),
			// Bounded at the agent's hard cap; see ClusterEventsMax. An unbounded
			// List makes the incident the Sentinel builds unloadable by the agent.
			Limit: ClusterEventsMax,
		})
	if err != nil {
		return nil, fmt.Errorf("telemetry: fetching events for uid %s: %s", podUID, RedactError(err))
	}
	return list.Items, nil
}

// boundedWriter stops accepting bytes after `remaining` and reports no error.
//
// io.Copy treats a short write as io.ErrShortWrite, which would turn the server
// exceeding LimitBytes into a failed fetch. Truncating is the correct behaviour:
// the bound is a cap, and a cap that turns into an error punishes exactly the
// noisiest container, which is the one most likely to be the incident.
type boundedWriter struct {
	w         io.Writer
	remaining int64
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	if b.remaining <= 0 {
		// Pretend the whole slice was consumed so io.Copy stops cleanly.
		return len(p), nil
	}
	if int64(len(p)) > b.remaining {
		if _, err := b.w.Write(p[:b.remaining]); err != nil {
			return 0, err
		}
		b.remaining = 0
		return len(p), nil
	}
	n, err := b.w.Write(p)
	b.remaining -= int64(n)
	return n, err
}

// PreviousLogsFor reports whether the evidence lives in the *previous*
// container instance.
//
// `previous` tells the kubelet to serve the log of the instance before the
// current one. Which instance holds the evidence depends entirely on what the
// container is doing at the moment of the fetch, and the two cases point in
// opposite directions:
//
//   - Terminated (OOMKilled): the current instance IS the one that died, and
//     its log is served without `previous`. Asking for the previous instance
//     either fails outright - on a first crash there is none - or, on a later
//     crash, silently serves an OLDER instance's log, which is evidence about
//     a different failure entirely.
//   - Waiting{CrashLoopBackOff}: the current instance is the one the kubelet
//     keeps failing to start, and it is blank by construction. The dead
//     instance is the previous one, so `previous` is correct.
//
// This returned true for both shapes, which asked every OOMKilled incident for
// the wrong instance's log. The failure is quiet: `Logs` reports a fetch error
// as empty logs, an empty log trivially contains no surviving secret, and it
// carries no mask marker either - so the redaction assertion fails with
// "nothing was masked" on a pipeline that is working perfectly. That is the
// signature the E2E detonation reported.
func PreviousLogsFor(kind FailureKind) bool {
	switch kind {
	case FailureCrashLoopBackOff:
		return true
	default:
		// OOMKilled, Terminated, and anything this watcher does not yet emit.
		// Defaulting to true is the safe-looking choice and is the unsafe one:
		// it is the value that silently reads the wrong instance.
		return false
	}
}
