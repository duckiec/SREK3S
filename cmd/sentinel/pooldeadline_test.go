package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/srek3s/sentinel/internal/emitter"
	"github.com/srek3s/sentinel/internal/k8s"
	"github.com/srek3s/sentinel/internal/metrics"
	"github.com/srek3s/sentinel/internal/worker"
)

// The pool's per-incident deadline is what bounds sink.Dispatch, so it - not
// emitter.DefaultTimeout - decides how long an agent has to answer. At the
// worker's own default (2 * k8s.TelemetryTimeout) that is 6s, against an agent
// whose documented worst case is 120s of model time: every Tier-2 incident is
// abandoned client-side and its verdict discarded while the agent keeps working.
//
// TestEmitterTimeoutExceedsAgentWorstCase cannot catch that. It compares
// emitter.DefaultTimeout against emitter.AgentMaxServiceTime, both declared in
// one file, and never observes a Pool. Two constants can agree while the deadline
// that binds them says otherwise, and that is what happened: the 5s -> 130s fix
// landed in the constant and left 6s in the pool.
//
// So this test asserts on the constructed Pool, which is the thing that actually
// imposes the deadline.

// TestTheProductionPoolDeadlineExceedsTheAgentWorstCase constructs the pool the
// way runWithFlags does and reads the deadline back.
//
// Constructed through a real emitter.Client, not a literal, so the assertion keeps
// tracking DefaultTimeout if that constant ever moves again.
func TestTheProductionPoolDeadlineExceedsTheAgentWorstCase(t *testing.T) {
	t.Parallel()

	// Through newPool, not through a pool assembled here: a test that builds its
	// own passes whether or not the daemon passes the same options.
	pool := newPool(nil, nil, &hangingSink{}, 2, slog.New(slog.DiscardHandler), metrics.New())

	deadline := pool.PerIncidentTimeout()
	t.Logf("pool perIncidentTimeout = %v", deadline)
	t.Logf("emitter.DefaultTimeout  = %v", deadline-emitter.DefaultTimeout == telemetryHeadroom)
	t.Logf("AgentMaxServiceTime     = %v", emitter.AgentMaxServiceTime)

	// The bound that matters: the pool must outlast the agent's worst case, or the
	// emitter's own timeout can never be reached.
	if deadline <= emitter.AgentMaxServiceTime {
		t.Errorf("pool deadline %v does not exceed the agent's worst case %v; "+
			"the emitter's %v budget is unreachable and every Tier-2 verdict is discarded",
			deadline, emitter.AgentMaxServiceTime, emitter.DefaultTimeout)
	}

	// And the regression in numbers: the worker default this replaces.
	stock := worker.New(nil, nil, &hangingSink{}, 2)
	if stock.PerIncidentTimeout() >= deadline {
		t.Errorf("expected the worker default %v to be shorter than the configured %v",
			stock.PerIncidentTimeout(), deadline)
	}
	t.Logf("worker default = %v (the value this fix replaces)", stock.PerIncidentTimeout())
}

// TestTheSinkIsNotAbandonedBeforeTheEmitterBudget proves the deadline is live, by
// running the real handle path against a sink that never returns and asserting it
// survives well past the 6s that used to abandon it.
//
// Bounded at 20s rather than the full 135s: the claim under test is that the sink
// is NOT cancelled at six seconds, and twenty seconds is more than enough to show
// six is not the deadline.
func TestTheSinkIsNotAbandonedBeforeTheEmitterBudget(t *testing.T) {
	t.Parallel()

	observed := make(chan time.Duration, 1)
	started := time.Now()
	records := make(chan *k8s.IncidentRecord, 1)
	records <- incidentForTest()
	close(records)
	pool := newPool(records, nil, &hangingSink{observed: observed}, 1, slog.New(slog.DiscardHandler), metrics.New())
	go pool.Run(context.Background())

	select {
	case <-observed:
		t.Fatalf("the sink was abandoned after %v, which is the 6s defect",
			time.Since(started).Round(time.Millisecond))
	case <-time.After(20 * time.Second):
		t.Logf("RESULT the sink was still running after %v, so the 6s abandonment is gone",
			time.Since(started).Round(time.Second))
	}
}

func incidentForTest() *k8s.IncidentRecord {
	return &k8s.IncidentRecord{
		DedupKey:      "uid/checkout-api:1",
		Namespace:     "payments",
		PodName:       "checkout-api-7d9f4b6c8d-x2k9p",
		PodUID:        "uid-checkout-api",
		ContainerName: "checkout-api",
		Kind:          k8s.FailureOOMKilled,
		ExitCode:      137,
		Restarts:      3,
	}
}

// hangingSink blocks until its context is cancelled, then reports.
type hangingSink struct{ observed chan time.Duration }

func (s *hangingSink) Dispatch(ctx context.Context, _ *worker.Incident) error {
	<-ctx.Done()
	if s.observed != nil {
		s.observed <- time.Since(time.Now())
	}
	return ctx.Err()
}
