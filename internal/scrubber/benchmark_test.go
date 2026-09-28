package scrubber

import (
	"context"
	"fmt"
	"testing"
)

// minLinesPerSecond is the ARCHITECTURE.md §6.2 budget: the full eleven-rule
// pipeline must sustain at least 20,000 lines/sec/core so masking stays far
// inside the 2 s detection budget (AC-1).
//
// The floor is relaxed for two build contexts where the figure is not a
// meaningful bar. Neither relaxation disables the check; both still catch an
// order-of-magnitude regression.
//
//   - Race-instrumented builds. ROADMAP 1.5.3 mandates `go test -race`, which
//     costs 5-20x. Without the relaxation the mandated gate could never be
//     green.
//   - Non-linux development hosts. The supported platforms are linux/amd64 and
//     linux/arm64 (k3s target, CI runner). Go's regexp is pure Go and its cost
//     differs materially by platform, so asserting the linux figure elsewhere
//     measures the host rather than the product.
//
// CI on ubuntu-latest is the authoritative measurement of the real target.
const (
	minLinesPerSecond              = 20000
	minLinesPerSecondUnderRace     = 2000
	minLinesPerSecondNonTarget     = 2000
	benchLineTarget            int = 10000 // representative slice size, ARCH §6.2
	_                          int = 0
)

// benchLines builds a representative log slice: mostly clean operational lines
// with roughly one secret-bearing line in seven, which is what real container
// telemetry looks like. A slice of pure secrets would measure the replacement
// path rather than the common one.
func benchLines(target int) []string {
	clean := []string{
		"2026-09-28T14:03:11.001Z INFO  checkout session started tenant=acme-corp latency_ms=42",
		"2026-09-28T14:03:11.117Z INFO  cache lookup key=cart:acme-corp hit=true backend=redis",
		"2026-09-28T14:03:11.233Z DEBUG pool checkout acquired conn id=1284 wait_ms=3",
		"2026-09-28T14:03:11.349Z WARN  retrying upstream call attempt=2 backoff_ms=100",
		"2026-09-28T14:03:11.455Z INFO  db query ok table=orders rows=17 duration_ms=8",
		"2026-09-28T14:03:11.561Z INFO  health probe /readyz status=200 duration_ms=2",
		"2026-09-28T14:03:11.673Z INFO  published checkout.completed partition=3 offset=88121",
		"2026-09-28T14:03:11.789Z INFO  span checkout.latency p99=184ms replica=checkout-api-7d9f",
	}
	secrets := []string{
		"dialing postgres://payments:hunter2@10.4.2.9:5432/payments",
		"auth password=sk-live-9f8a7b6c5d4e3f2a1b tenant=acme-corp",
		"signing aws_access_key_id=AKIAIOSFODNN7EXAMPLE region=us-east-1",
		"connect redis://cache-user:authToken99@redis.internal:6379/0",
		"notify contact=ops-oncall@example-corp.test subject=alert",
		"span trace 7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b duration_ms=7",
		"upstream Authorization: Bearer abc123def456ghi789jkl status=502",
		"peer dial 10.4.2.31:8443 node=checkout-node-2",
	}

	out := make([]string, 0, target/96+1)
	size := 0
	for i := 0; size < target; i++ {
		var line string
		if i%7 == 0 {
			line = secrets[(i/7)%len(secrets)]
		} else {
			line = clean[i%len(clean)]
		}
		out = append(out, line)
		size += len(line) + 1
	}
	return out
}

// linesPerSecondFloor returns the floor for the current build context.
func linesPerSecondFloor() (floor int, label string) {
	switch {
	case raceEnabled:
		return minLinesPerSecondUnderRace, "race-instrumented floor"
	case targetPlatform():
		return minLinesPerSecond, "target-platform floor"
	default:
		return minLinesPerSecondNonTarget, "unsupported dev host floor"
	}
}

// BenchmarkScrubThroughput is ROADMAP 1.4.9. Records lines/sec for the full
// pipeline so the figure can be quoted in the PR description.
//
// The workload is the shipped corpus, repeated to a representative batch size,
// so the ARCH §6.2 figure is measured against the same data the AC-2
// assertions verify rather than a separate synthetic fixture that could drift
// away from it.
func BenchmarkScrubThroughput(b *testing.B) {
	lines := corpusBenchmarkLines(b)
	ctx := context.Background()

	b.SetBytes(int64(len(lines) * 96))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ScrubLines(ctx, lines)
	}
}

// BenchmarkScrubThroughputSynthetic measures the original inline fixture. It is
// kept so the corpus-driven figure can be compared against a fixed workload
// across changes, since the corpus grows over time.
func BenchmarkScrubThroughputSynthetic(b *testing.B) {
	lines := benchLines(benchLineTarget)
	ctx := context.Background()

	b.SetBytes(int64(len(lines) * 96))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ScrubLines(ctx, lines)
	}
}

// TestThroughputMeetsBudget turns the ARCH §6.2 budget into an assertion.
//
// A benchmark only reports; it does not fail. A budget that is not asserted is
// a budget that silently regresses, so the same workload is measured here and
// checked against the floor.
func TestThroughputMeetsBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput assertion skipped in -short mode")
	}

	// Measured against the shipped corpus, so the asserted figure and the AC-2
	// assertions cover the same data.
	lines := corpusBenchmarkLines(t)
	floor, label := linesPerSecondFloor()
	ctx := context.Background()

	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = ScrubLines(ctx, lines)
		}
	})

	if res.N < 1 {
		t.Fatal("benchmark did not run")
	}
	// res.N counts iterations, and each iteration scrubs the whole slice, so
	// the line count must be multiplied in. Getting this wrong understates the
	// rate by a factor of the slice size.
	rate := float64(res.N) * float64(len(lines)) / res.T.Seconds()

	t.Logf("%.0f lines/sec over %d iterations of a %d line slice "+
		"(floor %d = %s, %s, race=%v, %.1f allocs/op)",
		rate, res.N, len(lines), floor, label, goPlatform(), raceEnabled,
		float64(res.AllocsPerOp()))

	if rate < float64(floor) {
		t.Errorf("throughput %.0f lines/sec is below the %d lines/sec floor (%s, %s, race=%v)",
			rate, floor, label, goPlatform(), raceEnabled)
	}
}

// TestBenchmarkFixtureExercisesSecrets guards the measurement itself: a
// throughput number taken over a slice with no secrets would be meaningless,
// because the replacement path is the expensive one.
func TestBenchmarkFixtureExercisesSecrets(t *testing.T) {
	t.Parallel()

	lines := benchLines(benchLineTarget)
	_, rep := ScrubLines(context.Background(), lines)

	if rep.Total == 0 {
		t.Fatal("benchmark fixture produced zero redactions")
	}
	if len(rep.RulesTriggered) < 4 {
		t.Errorf("fixture exercised only %d rules (%v); the throughput figure would be optimistic",
			len(rep.RulesTriggered), rep.RulesTriggered)
	}
	t.Log(fmt.Sprintf("fixture: %d lines, %d redactions across %v",
		len(lines), rep.Total, rep.RulesTriggered))
}
