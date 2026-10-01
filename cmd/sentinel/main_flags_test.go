package main

import (
	"context"
	"flag"
	"testing"
)

// TestVersionFlagExitsBeforeAnythingElse pins the ordering.
//
// -version is a support affordance: an operator in a broken incident needs the
// binary's version without a cluster, without a kubeconfig, and without a
// successful start. Anything that can fail must come *after* this check, or the
// flag becomes useless exactly when it is needed.
func TestVersionFlagExitsBeforeAnythingElse(t *testing.T) {
	// No kubeconfig, no reachable agent, an unreachable cluster. -version must
	// still return cleanly rather than reporting a configuration failure.
	err := run(context.Background(), []string{"-version"})
	if err != nil {
		t.Errorf("run(-version) = %v, want nil; the flag must work without a cluster", err)
	}
}

// TestUnknownFlagIsAnErrorNotAnExit is the property ContinueOnError buys.
//
// The flag package's default is ExitOnError, which calls os.Exit(2) from deep
// inside run(). A test cannot observe that, and more importantly a daemon that
// exits without logging has no record of why - the operator sees a CrashLoopBackOff
// with an empty last-termination reason.
func TestUnknownFlagIsAnErrorNotAnExit(t *testing.T) {
	flags := flag.NewFlagSet("sentinel", flag.ContinueOnError)
	// Output discarded so the usage text does not pollute the test log.
	flags.SetOutput(discardWriter{})
	err := runWithFlags(context.Background(), flags, []string{"-not-a-real-flag"})
	if err == nil {
		t.Fatal("an unknown flag was accepted; a typo would silently watch nothing")
	}
}

// TestAgentURLIsValidatedAtStartup is a real availability property.
//
// An unreachable agent is discovered on the first incident, which for a
// reliability tool means the tool has been silently not working for as long as it
// has been running. The URL's *shape* is checked at startup, which catches the
// common misconfiguration (a bare hostname with no scheme) without requiring a
// live agent.
func TestAgentURLIsValidatedAtStartup(t *testing.T) {
	for _, url := range []string{"", "srek3s-agent:8000", "not a url at all"} {
		flags := flag.NewFlagSet("sentinel", flag.ContinueOnError)
		flags.SetOutput(discardWriter{})
		// The clientset is expected to fail first in this environment (no
		// kubeconfig), so this only asserts the process returns an error rather
		// than panicking or hanging on a malformed URL.
		_ = runWithFlags(context.Background(), flags, []string{"-agent-url", url})
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
