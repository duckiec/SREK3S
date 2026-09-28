//go:build race

package scrubber

// raceEnabled reports whether the binary was built with -race.
//
// The race detector is the whole point of gate G3 (AGENTS.md §4), and it is the
// only tool that validates the shared-manifest concurrency claim in
// TestConcurrency. Its cost is why the throughput floor is relaxed when this is
// true. See race_off_test.go.
const raceEnabled = true
