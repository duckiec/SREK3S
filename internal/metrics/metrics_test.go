package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMetricsEndpointServesCounters drives a mock scrub event through the
// registry and asserts the exposition format carries it.
func TestMetricsEndpointServesCounters(t *testing.T) {
	t.Parallel()

	r := New()
	r.IncIntercepted()
	r.IncMasked("aws_access_key_id")
	r.IncMasked("aws_access_key_id")
	r.IncEmitterFailure()

	server := httptest.NewServer(r.Handler())
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		`srek3s_incidents_intercepted_total 1`,
		`srek3s_secrets_masked_total{rule="aws_access_key_id"} 2`,
		`srek3s_emitter_failures_total 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("exposition missing %q", want)
		}
	}

	if got := testutil.ToFloat64(r.IncidentsIntercepted); got != 1 {
		t.Errorf("intercepted = %v, want 1", got)
	}
}

// TestServeShutdownDoesNotPanic is a regression test for the double
// close(done) panic that fired on every SIGTERM. The metrics goroutine and
// Serve both closed the same channel.
func TestServeShutdownDoesNotPanic(t *testing.T) {
	r := New()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	if err := r.Serve(ctx, nil); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// TestNilRegistryIsNoOp proves a nil registry never panics, so the worker
// pool needs no configuration branch.
func TestNilRegistryIsNoOp(t *testing.T) {
	t.Parallel()

	var r *Registry
	r.IncIntercepted()
	r.IncMasked("jwt")
	r.IncEmitterFailure()
}
