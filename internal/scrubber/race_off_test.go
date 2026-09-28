//go:build !race

package scrubber

// raceEnabled reports whether the binary was built with -race.
//
// ROADMAP 1.5.3 mandates `go test -race`, which AGENTS.md §4 gate G3 also
// requires. The race detector costs 5-20x, so the throughput floor in
// TestThroughputMeetsBudget is relaxed when this is true. See race_on_test.go.
const raceEnabled = false
