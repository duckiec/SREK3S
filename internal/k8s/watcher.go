package k8s

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// EgressChannelCapacity is the depth of the incident queue.
//
// Bounded because an unbounded channel converts a burst of crash-looping pods
// into unbounded memory growth in the Sentinel - the daemon would be killed by
// the very incident it exists to report. At 100 it holds far more than the 2s
// detection budget (ARCH §7) can drain.
const EgressChannelCapacity = 100

// DedupTTL is how long a failure signature is suppressed.
//
// 60 seconds is chosen against the informer resync period, not in isolation: a
// resync re-delivers every object in the cache, so a TTL shorter than the resync
// period would suppress nothing, and one much longer would hide a genuine new
// failure. At a 30s resync, 60s suppresses each resync echo exactly once while
// still reporting a crash that recurs after a minute.
const DedupTTL = 60 * time.Second

// DefaultResyncPeriod is how often the informer replays its cache.
//
// Deliberately long. A resync is pure overhead for a daemon whose job is to
// react to change, and it is the *reason* deduplication exists at all - set it
// far above DedupTTL and the dedup logic would never be exercised.
const DefaultResyncPeriod = 30 * time.Second

// FailureKind distinguishes the two shapes this watcher recognises.
type FailureKind string

const (
	// FailureOOMKilled is a container that exited on its own limit. Exit code 137
	// is 128+SIGKILL, which is what the kernel sends when a cgroup exceeds its
	// memory limit.
	FailureOOMKilled FailureKind = "OOMKilled"
	// FailureCrashLoopBackOff is kubelet backing off from a container that keeps
	// failing to start.
	FailureCrashLoopBackOff FailureKind = "CrashLoopBackOff"
)

// IncidentRecord is one detected failure, ready for scrubbing and emission.
//
// Deliberately carries only identifiers and the state that classifies it. No log
// text and no event message reaches this struct: those are scrubbed in
// internal/scrubber before serialisation (ROADMAP 3.4.2), and a field here that
// held raw telemetry would be one more path for an unscrubbed string to escape
// through.
type IncidentRecord struct {
	// DedupKey is the signature used for suppression. See DedupKeyFor.
	DedupKey string

	Namespace     string
	PodName       string
	PodUID        string
	ContainerName string

	Kind      FailureKind
	ExitCode  int32
	Reason    string
	Message   string
	Restarts  int32
	PodPhase  corev1.PodPhase
	FirstSeen time.Time

	// PreviousReason is the termination reason of the instance *before* this one,
	// or "" when the container has never been restarted.
	//
	// From `LastTerminationState`, not from the current state. The kubelet
	// overwrites `State` when a container restarts, so by the time the Sentinel
	// sees a CrashLoopBackOff the only surviving evidence of the crash that caused
	// it is `LastTerminationState`. Reading `State` here would report the
	// CrashLoopBackOff itself, which is the condition and not the cause.
	PreviousReason string

	// Resources is the container's declared limits and requests, captured at
	// classification time from the pod spec, which is the only moment the object
	// is guaranteed to be in hand.
	//
	// Captured here rather than fetched by the worker because the worker talks to
	// a log and event API and would have to add a pod read to get a value the
	// informer already had - and a pod read at dispatch time can return a
	// *different* pod, after an edit, which would attribute a remediation to
	// limits that were never in force when the container died.
	Resources ContainerResources
}

// DedupKeyFor builds the deduplication signature.
//
// Format is exactly `"<podUID>/<containerName>:<restartCount>"`, per ROADMAP §3.3.3.
//
// Every component earns its place, and the container name is the one whose absence
// was an actual bug. An earlier version keyed on `"<namespace>/<podName>:<restartCount>"`,
// which carried no container component at all - so two containers failing in the
// *same* pod with the *same* restart count collided and one incident was silently
// suppressed. A sidecar OOMKill and an application CrashLoopBackOff are different
// incidents with different remediations; deduplicating one against the other is not
// deduplication, it is losing an incident.
//
// Pod UID rather than name matters for a second reason: a pod deleted and recreated
// under the same name restarts its restart counts at zero, so a name-keyed cache
// would treat a genuinely new failure of a replacement pod as a repeat of the old
// one and stay silent for the full TTL.
//
// The restart count makes the key correct rather than merely well-formatted: a
// crash-looping pod re-delivers the same status on every resync, and a key without
// the count would suppress those but also suppress a real new failure. Restart count
// increments when a container actually restarts, so it separates "the same failure,
// observed again" from "a new failure".
func DedupKeyFor(podUID types.UID, containerName string, restartCount int32) string {
	return fmt.Sprintf("%s/%s:%d", podUID, containerName, restartCount)
}

// dedupCache suppresses repeat deliveries of one signature.
//
// A map plus a timestamp rather than an LRU: the working set is bounded by the
// number of failing pods, and an LRU's eviction policy would silently decide
// which failures stop being deduplicated. Entries are swept on write, so the map
// cannot grow without bound when pods churn.
type dedupCache struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	now     func() time.Time
	ttl     time.Duration
	added   uint64
	dropped uint64
}

func newDedupCache(ttl time.Duration, now func() time.Time) *dedupCache {
	return &dedupCache{seen: make(map[string]time.Time), now: now, ttl: ttl}
}

// admit reports whether the key is new, and records it if so.
//
// The sweep runs inline rather than on a timer: a background sweeper would be a
// goroutine that exists only to trim a map, and this is bounded work on a path
// that runs once per pod event.
func (d *dedupCache) admit(key string) bool {
	now := d.now()

	d.mu.Lock()
	defer d.mu.Unlock()

	// Sweep expired entries first, so the map size tracks *live* failures.
	for k, at := range d.seen {
		if now.Sub(at) >= d.ttl {
			delete(d.seen, k)
		}
	}

	if at, ok := d.seen[key]; ok && now.Sub(at) < d.ttl {
		d.dropped++
		return false
	}
	d.seen[key] = now
	d.added++
	return true
}

func (d *dedupCache) stats() (added, dropped uint64, size int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.added, d.dropped, len(d.seen)
}

// classify extracts the failures worth reporting from a pod.
//
// Returns one record per failing container, so a pod with an OOMKilled app and a
// crash-looping sidecar produces both. A nil pod, a nil-heavy status tree, or a
// healthy container all yield nothing rather than panicking - which is the whole
// point of the guard accessors.
//
// The two conditions are checked against the *spec* container list, not the
// status list, because a container with no status entry still has to be visited
// and dismissed; iterating statuses instead would silently skip any container the
// kubelet has not yet reported.
func classify(pod *corev1.Pod, now time.Time) []IncidentRecord {
	if pod == nil {
		return nil
	}

	statuses := pod.Status.ContainerStatuses
	records := make([]IncidentRecord, 0, len(pod.Spec.Containers))

	for i := range pod.Spec.Containers {
		container := pod.Spec.Containers[i]
		if container.Name == "" {
			continue
		}
		status := StatusForContainer(statuses, container.Name)
		if status == nil {
			// Admitted but not yet reported by the kubelet. Not a failure.
			continue
		}

		restarts := RestartCount(status)
		// Pod UID and container name, not namespace and pod name. See
		// DedupKeyFor: omitting the container name made two failing containers in
		// one pod collide, which suppressed a real incident.
		key := DedupKeyFor(pod.UID, container.Name, restarts)

		// Terminated with a non-zero exit. Exit code 137 is SIGKILL from the
		// memory cgroup; other non-zero exits are application errors.
		//
		// A non-OOM termination is DROPPED here rather than reported. Two
		// reasons, and the second is the one that was a bug.
		//
		// First, there is nowhere to put it. Contract A's `reason` admits
		// OOMKilled and CrashLoopBackOff only, so `emitter.mapReason` refuses
		// everything else and rejects the incident before it reaches the wire.
		// A record that cannot be serialised should not be built.
		//
		// Second, and this is what it actually cost: the dedup key is
		// `<podUID>/<containerName>:<restartCount>` and does not include the
		// kind. A transient `Terminated{exit 1}` at restart N therefore claims
		// the key that `Waiting{CrashLoopBackOff}` at the same restart N needs,
		// and the symptom - which is the state carrying the evidence - is
		// suppressed as a duplicate. A crash-looping container was detected and
		// then never reported at all.
		//
		// Filtering here, before the record exists, is what stops the
		// un-serialisable state from poisoning the cache in the first place.
		// Mapping it to CrashLoopBackOff instead would report the kubelet
		// asserting a state the Sentinel has not observed.
		if term := TerminationOf(status); term.Found && term.ExitCode != 0 {
			kind := classifyExit(term)
			if kind != FailureOOMKilled {
				continue
			}
			records = append(records, IncidentRecord{
				DedupKey:       key,
				Namespace:      pod.Namespace,
				PodName:        pod.Name,
				PodUID:         string(pod.UID),
				ContainerName:  container.Name,
				Kind:           kind,
				ExitCode:       term.ExitCode,
				Reason:         term.Reason,
				Message:        term.Message,
				Restarts:       restarts,
				PodPhase:       pod.Status.Phase,
				FirstSeen:      now,
				PreviousReason: LastTerminationOf(status).Reason,
				Resources:      ResourcesFor(pod, container.Name),
			})
			continue
		}

		// Waiting in CrashLoopBackOff. The kubelet holds the reason here and
		// clears Terminated, so this is a genuinely different shape rather than a
		// duplicate of the branch above.
		if waiting := WaitingOf(status); waiting.Found && waiting.Reason == string(FailureCrashLoopBackOff) {
			records = append(records, IncidentRecord{
				DedupKey:       key,
				Namespace:      pod.Namespace,
				PodName:        pod.Name,
				PodUID:         string(pod.UID),
				ContainerName:  container.Name,
				Kind:           FailureCrashLoopBackOff,
				ExitCode:       0,
				Reason:         waiting.Reason,
				Message:        waiting.Message,
				Restarts:       restarts,
				PodPhase:       pod.Status.Phase,
				FirstSeen:      now,
				PreviousReason: LastTerminationOf(status).Reason,
				Resources:      ResourcesFor(pod, container.Name),
			})
		}
	}

	return records
}

// OOMExitCode is 128 + SIGKILL(9), what the kernel sends a cgroup over its
// memory limit.
const OOMExitCode int32 = 137

func classifyExit(term Termination) FailureKind {
	if term.ExitCode == OOMExitCode || term.Reason == string(FailureOOMKilled) {
		return FailureOOMKilled
	}
	return FailureKind("Terminated")
}

// PodWatcher observes pod state and emits deduplicated incident records.
//
// Informer callbacks run on a shared, single-goroutine work queue, which means a
// callback that blocks stalls every pod in the cluster. That is why the egress
// send is non-blocking and drops on a full queue: losing one incident is
// recoverable and reported by the queue depth; stalling the informer is not
// recoverable and is not observable at all.
type PodWatcher struct {
	client   kubernetes.Interface
	events   chan *IncidentRecord
	factory  informers.SharedInformerFactory
	informer cache.SharedInformer

	// resync and namespace are held as fields rather than being applied
	// immediately by their options. The first version had `WithResyncPeriod`
	// rebuild the factory, which meant option *order* silently decided whether
	// a namespace scope survived: applying `WithResyncPeriod` after
	// `WithNamespace` would rebuild the factory without the namespace and the
	// Sentinel would quietly widen back to watching everything. Building the
	// factory once, after every option has run, removes the hazard by making it
	// unrepresentable.
	resync    time.Duration
	namespace string

	dedup *dedupCache
	now   func() time.Time
	log   *slog.Logger

	mu      sync.Mutex
	dropped uint64
	emitted uint64
}

// WatcherOption configures a [PodWatcher].
type WatcherOption func(*PodWatcher)

// WithClock overrides the clock, so TTL behaviour is testable without sleeping.
func WithClock(now func() time.Time) WatcherOption {
	return func(w *PodWatcher) { w.now = now; w.dedup = newDedupCache(DedupTTL, now) }
}

// WithLogger sets the logger. Defaults to slog.Default().
func WithLogger(log *slog.Logger) WatcherOption {
	return func(w *PodWatcher) { w.log = log }
}

// WithResyncPeriod overrides the informer resync period.
func WithResyncPeriod(d time.Duration) WatcherOption {
	return func(w *PodWatcher) { w.resync = d }
}

// WithNamespace restricts the watch to a single namespace.
//
// Empty means all namespaces, which is client-go's own convention for a namespaced
// resource and is why the zero value is the permissive one.
//
// This is a blast-radius control, not a performance knob. An all-namespaces
// Sentinel will emit an incident for every failing container in the cluster,
// including in namespaces it has no business observing, and the agent will spend
// its job budget triaging them. ROADMAP 4.1.5 makes it a guardrail: a chaos
// fixture in `sentinel-chaos` must be visible, and a production namespace must
// not be, when the Sentinel is pointed at chaos.
//
// The scope is enforced by the informer's own List/Watch, not by filtering
// afterwards. Filtering post-hoc would still pay the full cost of watching the
// whole cluster and would make the exclusion depend on a code path that a bug
// could bypass.
func WithNamespace(namespace string) WatcherOption {
	return func(w *PodWatcher) { w.namespace = namespace }
}

// Namespace reports the scope the watcher was built with, and whether it is
// cluster-wide.
//
// Exposed so main can log the value that was actually applied rather than the
// value it intended. An earlier version logged the `-namespace` flag while the
// informer ignored it entirely, so the log asserted a scoping that was not in
// effect.
func (w *PodWatcher) Namespace() (string, bool) {
	return w.namespace, w.namespace == AllNamespaces
}

// NewPodWatcher builds a watcher over a pod informer.
//
// The factory is created here and the informer taken from it, so the factory is
// retained: without a reference it can be garbage collected and the informer
// stops receiving resyncs and event deliveries, which is a failure mode that looks
// like "the cluster went quiet" rather than like a bug.
func NewPodWatcher(client kubernetes.Interface, opts ...WatcherOption) *PodWatcher {
	w := &PodWatcher{
		client: client,
		events: make(chan *IncidentRecord, EgressChannelCapacity),
		resync: DefaultResyncPeriod,
		now:    time.Now,
		log:    slog.Default(),
	}
	for _, opt := range opts {
		opt(w)
	}
	if w.dedup == nil {
		w.dedup = newDedupCache(DedupTTL, w.now)
	}

	// Built once, after every option, so no option can be silently discarded by
	// a later one rebuilding the factory. See the resync field's comment.
	factoryOptions := make([]informers.SharedInformerOption, 0, 1)
	if w.namespace != AllNamespaces {
		factoryOptions = append(factoryOptions, informers.WithNamespace(w.namespace))
	}
	w.factory = informers.NewSharedInformerFactoryWithOptions(
		w.client, w.resync, factoryOptions...,
	)

	w.informer = w.factory.Core().V1().Pods().Informer()
	if _, err := w.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			w.onAdd(obj)
		},
		UpdateFunc: func(old, obj any) {
			w.onUpdate(old, obj)
		},
	}); err != nil {
		// client-go has never returned an error here, but swallowing one would
		// mean a silently event-less watcher, so it is surfaced at construction.
		w.log.Error("failed to register pod event handler", "error", RedactError(err))
	}
	return w
}

// Events returns the incident channel.
//
// The single consumer is expected to range over it; the channel is closed when
// the watcher stops.
func (w *PodWatcher) Events() <-chan *IncidentRecord { return w.events }

// Run starts the informer and blocks until stop is closed.
//
// The context is used for the factory's lifecycle, and stop is honoured before
// the channel is closed, so a consumer ranging over Events sees the channel end
// rather than blocking forever. AGENTS.md §3.2: bounded and cancellable.
func (w *PodWatcher) Run(stop <-chan struct{}) {
	// Defer order is load-bearing, and it is LIFO. close(w.events) is registered
	// first so it runs LAST; factory.Shutdown() is registered second so it runs
	// FIRST. Shutdown synchronously waits - client-go v0.31:
	// sharedInformerFactory.Shutdown calls wg.Wait(), over sharedIndexInformer.Run's
	// deferred wg.Wait() over processor.run, which itself p.wg.Wait()s over the
	// listener goroutines that invoke our handlers - until every handler has
	// returned. Only then does close(w.events) run, so no handler can execute its
	// select-send on the closed channel. Without this the handler goroutines
	// outlive Run's return: a handler dispatched in the window after stop closes
	// hits `select { case w.events <- record: ... }` with a closed channel, which
	// is "ready", so the send is chosen and panics.
	defer close(w.events)
	defer w.factory.Shutdown()
	w.factory.Start(stop)
	if !cache.WaitForCacheSync(stop, w.informer.HasSynced) {
		w.log.Error("pod informer cache did not sync before shutdown")
		return
	}
	w.log.Info("pod watcher started",
		// The APPLIED period, not the DefaultResyncPeriod constant. WithResyncPeriod
		// changes w.resync, and logging the constant while running a different value
		// is how an operator deduces the wrong resync cadence from the log.
		"resync", w.resync,
		"dedup_ttl", DedupTTL.String(),
		"egress_capacity", EgressChannelCapacity,
	)
	<-stop
	w.log.Info("pod watcher stopped",
		"emitted", w.Stats().Emitted,
		"dropped", w.Stats().Dropped,
	)
}

// onAdd handles the informer's initial list, which contains every existing pod
// rather than only new ones.
func (w *PodWatcher) onAdd(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		// DeletedFinalStateUnknown arrives here on a delete that raced a resync.
		w.log.Debug("ignoring non-pod object from informer", "type", fmt.Sprintf("%T", obj))
		return
	}
	w.handle(pod)
}

// onUpdate handles a pod change.
//
// The previous object is accepted and ignored on purpose: a pod that moves from
// Running to OOMKilled must be reported, and deciding that from the new object
// alone is sufficient. Comparing against the previous object would suppress the
// transition this watcher exists to catch.
func (w *PodWatcher) onUpdate(_, obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	w.handle(pod)
} // handle classifies, deduplicates and enqueues.
func (w *PodWatcher) handle(pod *corev1.Pod) {
	records := classify(pod, w.now())
	for i := range records {
		record := records[i]
		if !w.dedup.admit(record.DedupKey) {
			continue
		}
		w.emit(&record)
	}
}

// emit performs the non-blocking send.
//
// A non-blocking send is the whole design of this egress. The informer callback
// thread must never block: blocking it stalls the shared work queue that
// delivers events for *every* pod in the cluster, so one full channel would turn
// a burst of crashes into a cluster-wide observation freeze.
func (w *PodWatcher) emit(record *IncidentRecord) {
	select {
	case w.events <- record:
		w.mu.Lock()
		w.emitted++
		w.mu.Unlock()
	default:
		w.mu.Lock()
		w.dropped++
		dropped := w.dropped
		w.mu.Unlock()
		w.log.Warn("egress channel full, dropping incident",
			"dropped_total", dropped,
			"namespace", record.Namespace,
			"pod", record.PodName,
			"container", record.ContainerName,
			"kind", string(record.Kind),
		)
	}
}

// WatcherStats is a snapshot of watcher counters.
type WatcherStats struct {
	Emitted         uint64
	Dropped         uint64
	DedupAdmitted   uint64
	DedupSuppressed uint64
	DedupSize       int
	QueueDepth      int
}

// Stats returns a point-in-time snapshot.
//
// The counters are separate mutexes, so the snapshot is not atomic across
// fields. That is acceptable and stated rather than hidden: this feeds a log line
// and a health endpoint, and a single extra lock to make three numbers consistent
// is not worth the contention on the emit path.
func (w *PodWatcher) Stats() WatcherStats {
	w.mu.Lock()
	emitted, dropped := w.emitted, w.dropped
	w.mu.Unlock()
	added, suppressed, size := w.dedup.stats()
	return WatcherStats{
		Emitted:         emitted,
		Dropped:         dropped,
		DedupAdmitted:   added,
		DedupSuppressed: suppressed,
		DedupSize:       size,
		QueueDepth:      len(w.events),
	}
}
