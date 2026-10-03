package scrubber

import "runtime"

// targetPlatform reports whether this build runs on a platform SREK3S
// supports: linux/amd64 (the k3s deployment target and the CI runner) or
// linux/arm64.
//
// The CONTRIBUTING.md §5.2 throughput budget of 20,000 lines/sec/core is stated for that
// platform. Go's regexp is pure Go and its cost varies materially by
// architecture, so the budget is only enforced at full strength here; other
// build contexts use a reduced floor. See linesPerSecondFloor.
//
// This file deliberately has NO build tag. An earlier version defined these
// helpers in a file tagged `!race`, which meant that under `-race` — the exact
// build AGENTS.md §4 gate G3 requires — the symbols were undefined and the
// package failed to compile. The helper is platform logic, not race logic, so
// it must be present in every build. Only raceEnabled, which genuinely varies,
// is behind a build tag.
func targetPlatform() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	return runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
}

// goPlatform renders the current build platform for log messages.
func goPlatform() string { return runtime.GOOS + "/" + runtime.GOARCH }
