//go:build race

package scrubber

// targetPlatform is defined once, in platform_off_test.go. The race build tag
// only changes the raceEnabled constant, not the platform detection, so no
// duplicate is needed here.
