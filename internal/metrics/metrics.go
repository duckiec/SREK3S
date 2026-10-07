// Package metrics exposes the Sentinel's operational telemetry for Prometheus.
//
// The registry is private to this package and served on :9090 by cmd/sentinel
// in a dedicated goroutine. It never shares a listener with the emitter path,
// and a nil *Registry is a no-op, so callers never branch on configuration.
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Addr is the metrics listener. A fixed port, not a flag: Prometheus scrapes
// by address, and an operator who moves it must update the scrape config, the
// NetworkPolicy, and the pod annotations together.
const Addr = ":9090"

// Registry holds the Sentinel's counters and the registry they are bound to.
//
// The registry is private so no other package can register series into it.
// Unknown series in a scrape target are how a dashboard starts asserting things
// nobody owns.
type Registry struct {
	reg *prometheus.Registry

	// IncidentsIntercepted counts admitted incidents, before dispatch.
	IncidentsIntercepted prometheus.Counter
	// SecretsMasked counts scrubber rule firings, one per triggered rule per
	// incident. It is a firing count, not a redaction count: the report
	// deliberately exposes only {Total, RulesTriggered} (CONTRIBUTING.md §5.1
	// M4), so per-redaction attribution does not exist to export.
	SecretsMasked *prometheus.CounterVec
	// EmitterFailures counts incidents the emitter could not deliver.
	EmitterFailures prometheus.Counter
}

// New builds the registry and its three counters.
func New() *Registry {
	r := &Registry{reg: prometheus.NewRegistry()}
	r.IncidentsIntercepted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "srek3s",
		Name:      "incidents_intercepted_total",
		Help:      "Admitted incidents, before dispatch.",
	})
	r.SecretsMasked = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "srek3s",
		Name:      "secrets_masked_total",
		Help:      "Scrubber rule firings, one per triggered rule per incident.",
	}, []string{"rule"})
	r.EmitterFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "srek3s",
		Name:      "emitter_failures_total",
		Help:      "Incidents the emitter could not deliver.",
	})
	r.reg.MustRegister(r.IncidentsIntercepted, r.SecretsMasked, r.EmitterFailures)
	return r
}

// Handler serves the registry for scraping.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// Serve runs the metrics listener until ctx ends. It returns when the server
// has shut down; a bind failure is returned, not logged, so the caller decides
// whether metrics are worth crashing over. (They are not: main logs and runs
// without them.)
func (r *Registry) Serve(ctx context.Context, log *slog.Logger) error {
	server := &http.Server{
		Addr:              Addr,
		Handler:           r.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutCtx)
		}
	}()
	if log != nil {
		log.Info("metrics listening", "addr", Addr)
	}
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// IncIntercepted records one admitted incident. Nil-safe: a nil registry
// records nothing, so the worker pool never branches on configuration.
func (r *Registry) IncIntercepted() {
	if r == nil {
		return
	}
	r.IncidentsIntercepted.Inc()
}

// IncMasked records one firing of the named rule. Nil-safe, as above.
func (r *Registry) IncMasked(rule string) {
	if r == nil {
		return
	}
	r.SecretsMasked.WithLabelValues(rule).Inc()
}

// IncEmitterFailure records one undelivered incident. Nil-safe, as above.
func (r *Registry) IncEmitterFailure() {
	if r == nil {
		return
	}
	r.EmitterFailures.Inc()
}
