//go:build !race

package scrubber

import "runtime"

// targetPlatform reports whether this build runs on a platform SREK3S
// supports: linux/amd64 (the k3s deployment target and the CI runner) or
// linux/arm64.
//
// The ARCH §6.2 throughput budget of 20,000 lines/sec/core is stated for that
// platform. Go's regexp is pure Go and its cost varies materially by
// architecture, so the budget is only enforced at full strength here and
// elsewhere a reduced floor applies. See TestThroughputMeetsBudget.
func targetPlatform() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	return runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
}

// goPlatform renders the current build platform for log messages.
func goPlatform() string { return runtime.GOOS + "/" + runtime.GOARCH }
