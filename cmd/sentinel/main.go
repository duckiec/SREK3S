// Command sentinel is the SREK3S Sentinel: it watches pods, scrubs and classifies
// container failures in memory, and emits them to the analysis agent.
//
// It holds no authority to change anything. The cluster Role it runs under is
// get/list/watch only, and every remediation it produces leaves as a unified diff
// in a request body. That constraint is the product, not a limitation of it.
//
// # Shutdown
//
// The shutdown path is the part of this file worth reading. On SIGINT or SIGTERM
// the root context is cancelled, which stops the informer and the worker pool, and
// then main *waits* for the pool's WaitGroup to drain before returning. Without
// that wait, `os.Exit` would abandon goroutines mid-request: a container that
// OOM-killed at the moment of the signal would be classified, scrubbed, and then
// dropped on the floor with no record that it happened. For a reliability tool the
// incidents during its own restart are exactly the ones worth having.
//
// The drain is bounded by [ShutdownGrace]. Kubernetes sends SIGTERM and then waits
// `terminationGracePeriodSeconds` before SIGKILL, so a graceful shutdown that
// exceeds the grace period is not graceful - it is a second hard kill, with less
// information. Bounding the wait keeps the failure mode "some telemetry was lost,
// and we said so" rather than "the process was killed mid-write".
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/srek3s/sentinel/internal/emitter"
	"github.com/srek3s/sentinel/internal/k8s"
	"github.com/srek3s/sentinel/internal/worker"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

// Defaults, all overridable by flag. Every one of them is a bound on resource use
// or on time spent blocking, so none of them is a tuning knob that should be set
// by accident at startup.
const (
	// ShutdownGrace is how long main waits for the pool to drain before giving up
	// and reporting the loss.
	//
	// Must be shorter than the Deployment's terminationGracePeriodSeconds, or the
	// kubelet SIGKILLs the process mid-drain and the wait is decorative.
	ShutdownGrace = 20 * time.Second

	// MetricsInterval is the periodic stats log. Frequent enough to be useful in a
	// short incident, sparse enough not to be noise in a long one.
	MetricsInterval = 30 * time.Second
)

func main() {
	// signal.NotifyContext, rather than a goroutine per signal. It cancels the
	// context on the first SIGINT/SIGTERM and, crucially, arranges for a *second*
	// one to have the default behaviour restored so an operator can always
	// escalate to an immediate kill.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		// Exit codes are load-bearing for a daemon: 1 is a configuration or
		// startup failure, which an orchestrator should surface as a crash loop
		// rather than a pod that looks alive and watches nothing.
		slog.Error("sentinel exited", "error", err)
		os.Exit(1)
	}
}

// run is main's body, parameterised on its two environmental inputs: a context
// that carries the shutdown signal, and the argument list.
//
// The split is what makes the shutdown path testable. Wiring signals is the one
// part of a daemon that cannot be exercised in-process - a test cannot raise
// SIGTERM against itself without disturbing the test binary - so the signal
// handler is the only thing in main(), and everything it drives is here where a
// test can cancel a context instead.
func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("sentinel", flag.ContinueOnError)
	return runWithFlags(ctx, flags, args)
}

func runWithFlags(ctx context.Context, flags *flag.FlagSet, args []string) error {
	// Registered on the injected FlagSet, not the package-level one.
	//
	// Using `flag.String` here would register on flag.CommandLine, so two
	// invocations of run in one test binary would panic on duplicate flag
	// definition - and a panic in a test looks exactly like a defect in the code
	// under test. `flags.String` binds to the set the caller owns.
	var (
		kubeconfig  = flags.String("kubeconfig", "", "path to a kubeconfig; empty uses in-cluster config")
		agentURL    = flags.String("agent-url", envOr("SREK3S_AGENT_URL", "http://srek3s-agent:8080"), "base URL of the analysis agent")
		namespace   = flags.String("namespace", os.Getenv("WATCH_NAMESPACE"), "namespace to watch; empty watches all")
		workers     = flags.Int("workers", worker.DefaultPoolSize, "number of worker goroutines")
		logLevel    = flags.String("log-level", envOr("LOG_LEVEL", "info"), "debug, info, warn or error")
		showVersion = flags.Bool("version", false, "print the version and exit")
	)
	// ContinueOnError, so a bad flag returns an error instead of calling
	// os.Exit(2) from inside a function that a test is calling. The flag package's
	// default ExitOnError would make every parse failure untestable and would
	// bypass the log line the operator actually reads.
	if err := flags.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	log := newLogger(*logLevel)
	slog.SetDefault(log)

	if ctx == nil {
		ctx = context.Background()
	}

	log.Info("sentinel starting",
		"version", version,
		"namespace", namespaceOrAll(*namespace),
		"workers", *workers,
		"agent_url", *agentURL,
	)

	client, err := k8s.NewClientset(*kubeconfig)
	if err != nil {
		// RedactError before logging. A clientset construction failure is one of the
		// few places a bearer token or a kubeconfig path can reach an error string,
		// and this process's logs are the one channel an operator is guaranteed to
		// paste into a ticket.
		var configErr *k8s.SentinelConfigError
		if errors.As(err, &configErr) {
			return fmt.Errorf("kubernetes client: %s", k8s.RedactError(err))
		}
		return fmt.Errorf("kubernetes client: %w", err)
	}

	// The informer factory's constructor requires a kubernetes.Interface, so a
	// read-only facade cannot be the thing handed to the watcher - client-go has no
	// read-only informer variant. The guarantee is therefore enforced two other
	// ways, and this is the honest accounting of them:
	//
	//   - The RBAC Role (ROADMAP 3.6.2) grants get/list/watch and nothing else, so
	//     a write attempt would be rejected by the apiserver rather than by this
	//     process. That is the load-bearing control and it lives outside the code.
	//   - TestNoMutatingCallsInSources parses this package's AST and fails on any
	//     Create, Update, Patch, Delete or DeleteCollection call, so the code cannot
	//     acquire the capability the Role declines to grant.
	//
	// The facade in readonly.go is the third layer: it is what any *new* application
	// code should use, and its absence here is dictated by client-go's signature
	// rather than chosen.
	readOnly := k8s.NewReadOnlyClientset(client)
	if namespace := *namespace; namespace != "" {
		log.Info("scoping the watch", "namespace", namespace,
			"reader", k8s.DescribeReadOnlyClientset(readOnly, namespace))
	} else {
		log.Info("watching all namespaces",
			"reader", k8s.DescribeReadOnlyClientset(readOnly, k8s.AllNamespaces))
	}

	watcher := k8s.NewPodWatcher(client, k8s.WithLogger(log))

	telemetry := k8s.NewTelemetry(client)

	sink, err := emitter.New(emitter.Config{
		BaseURL:         *agentURL,
		SentinelVersion: version,
		Events:          eventConverter,
	})
	if err != nil {
		return fmt.Errorf("emitter: %w", err)
	}
	// Closes the transport's idle connections on the way out, so a rolling update
	// does not leave the process waiting on keep-alives to the old agent.
	defer sink.Close()

	pool := worker.New(
		watcher.Events(),
		telemetry,
		sink,
		*workers,
		worker.WithLogger(log),
	)

	// The informer runs in the background against a stop channel, because
	// SharedInformerFactory's API predates context. The bridging goroutine is the
	// price of that API and is the one extra goroutine main owns.
	stopInformer := make(chan struct{})
	var informerDone sync.WaitGroup
	informerDone.Add(1)
	go func() {
		defer informerDone.Done()
		watcher.Run(stopInformer)
	}()

	// The pool is started separately from Run so the drain below can be explicit.
	pool.Start(ctx)

	log.Info("sentinel running")

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		pool.Wait()
	}()

	// Periodic stats. Ends with the process, and logs a final snapshot through the
	// same path, so the last thing in the log before exit is the state at exit.
	tickerDone := make(chan struct{})
	go func() {
		defer close(tickerDone)
		ticker := time.NewTicker(MetricsInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				logStats(log, watcher.Stats(), pool.Stats())
			}
		}
	}()

	<-ctx.Done()
	log.Info("shutdown signal received; draining in-flight telemetry",
		"grace", ShutdownGrace,
		"in_flight", pool.Stats().InFlight,
	)

	// Order matters, and it is the reverse of the startup order.
	//
	// 1. Stop the informer first, so no new work is produced. Draining first and
	//    stopping second would let the queue keep refilling while we wait for it to
	//    empty, and the wait would never finish.
	close(stopInformer)
	informerDone.Wait()

	// 2. Then wait for the pool, bounded. ctx is already cancelled, so in-flight
	//    telemetry fetches are cut short by their own per-call deadlines - which is
	//    the reason those deadlines exist and are short. The pool's workers see the
	//    cancellation between records and exit promptly.
	drained := waitFor(stopped, ShutdownGrace)
	if !drained {
		log.Error("drain did not complete within the grace period; "+
			"some in-flight telemetry was lost. Raise terminationGracePeriodSeconds "+
			"to match, or lower the per-incident telemetry timeout",
			"grace", ShutdownGrace,
			"in_flight", pool.Stats().InFlight,
		)
		close(tickerDone)
		return errors.New("shutdown drain timed out")
	}
	close(tickerDone)

	logStats(log, watcher.Stats(), pool.Stats())
	log.Info("sentinel stopped cleanly",
		"processed", pool.Stats().Processed,
		"failed", pool.Stats().Failed,
	)
	return nil
}

// waitFor reports whether done closed within the timeout.
//
// time.After rather than a reused Ticker: this is called once, at shutdown, and a
// timer that is never stopped here would be a leak in a process that is about to
// exit anyway - but the explicit drain keeps the intent obvious.
func waitFor(done <-chan struct{}, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// logStats writes one snapshot line per subsystem.
//
// Counters are cumulative, so this reads as a heartbeat rather than a rate. A rate
// would need a previous sample to subtract from, and the first sample would have
// no baseline to report.
func logStats(log *slog.Logger, watcher k8s.WatcherStats, pool worker.Stats) {
	log.Info("stats",
		"watcher_emitted", watcher.Emitted,
		"watcher_dropped", watcher.Dropped,
		"watcher_queue_depth", watcher.QueueDepth,
		"dedup_admitted", watcher.DedupAdmitted,
		"dedup_suppressed", watcher.DedupSuppressed,
		"dedup_size", watcher.DedupSize,
		"processed", pool.Processed,
		"failed", pool.Failed,
		"in_flight", pool.InFlight,
	)
}

// eventConverter turns a scrubbed incident's event messages into wire events.
//
// It takes the incident, not *corev1.Event objects, and that is the whole design.
// The worker deliberately does not retain the event objects - only their scrubbed
// messages - so rebuilding a ClusterEvent from what survived is the only
// construction that cannot reintroduce unscrubbed Kubernetes text into the request
// body. ROADMAP 3.4.2 asks for a code path that cannot serialise raw telemetry;
// this is it.
//
// The cost is that the structured fields the kubelet knew - `reason`, `count`,
// timestamps - are gone by this point, because they lived on the event objects and
// those did not survive scrubbing. They are filled from the incident identity,
// which is what the agent's RCA actually needs, and the ones that cannot be
// derived are emitted as null rather than invented. `involved_object` is
// reconstructed from the incident's own namespace and pod name - the one object
// these events could have involved, since the join was on the pod UID.
//
// The alternative - keeping the event objects through the worker and scrubbing them
// field by field - would be more faithful, and would also put a Kubernetes struct
// with nine unscrubbed string fields one careless `json.Marshal` away from the wire.
func eventConverter(incident *worker.Incident) []emitter.ClusterEvent {
	if incident == nil {
		return nil
	}
	messages := incident.ScrubbedEventMessages
	if len(messages) == 0 {
		return nil
	}

	// `pod/<name>` matches the form in the agent's canonical sample fixture. The
	// namespace is not part of the reference because the object is addressed
	// cluster-wide by UID in the field selector the fetch used.
	involvedObject := "pod/" + incident.PodName
	if incident.PodName == "" {
		// No pod name means no object reference. Emitted as an absent field would
		// fail the agent's min_length of 3 and take the whole payload with it, so
		// the events are dropped instead. The message is still in scrubbed_logs.
		return nil
	}

	events := make([]emitter.ClusterEvent, 0, len(messages))
	for _, message := range messages {
		if message == "" {
			continue
		}
		events = append(events, emitter.ClusterEvent{
			// "Warning" is the only type a container failure produces, and the
			// agent's model rejects anything else. A Normal Event is not evidence of
			// a failure.
			Type:    string(corev1.EventTypeWarning),
			Reason:  incident.Kind,
			Message: message,
			// Count is required and non-negative. One deduplicated incident
			// corresponds to one event, because the watcher already collapsed
			// repeats into a single record.
			Count:          1,
			InvolvedObject: involvedObject,
		})
	}
	return events
}

func newLogger(level string) *slog.Logger {
	var parsed slog.Level
	if err := parsed.UnmarshalText([]byte(level)); err != nil {
		// A bad level is not worth refusing to start over: the safe default is the
		// one that logs. Failing here would mean a typo in a ConfigMap takes the
		// reliability monitor down, which is a worse outcome than verbose logs.
		parsed = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parsed}))
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func namespaceOrAll(namespace string) string {
	if namespace == "" {
		return "(all)"
	}
	return namespace
}

var _ = metav1.Now
