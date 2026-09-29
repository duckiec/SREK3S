// Package k8s provides the Sentinel's read-only view of a cluster.
//
// Everything in this package observes. Nothing here writes, and that is a
// structural property rather than a convention: see [ClientsetOnly] for how it
// is enforced by a test rather than by review.
package k8s

import (
	"errors"
	"fmt"
	"os"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// DefaultConfigTimeout bounds how long a client may spend resolving
// configuration. AGENTS.md §3.2 requires every blocking operation to be
// deadline-bounded; a client that hangs during startup is a Sentinel that never
// starts watching, which is a Sentinel that misses every incident.
const DefaultConfigTimeout = 15 * time.Second

// SentinelConfigError reports a failure to build a client, with the underlying
// cause preserved but the credential material it may contain removed.
//
// In-cluster configuration failures routinely carry the path to a service-account
// token, and a token path in a log is half a credential. The sentinel wrapper
// exists so the wrapped error can be logged without thought.
type SentinelConfigError struct {
	// Source names which configuration method failed: "in-cluster" or "kubeconfig".
	Source string
	// Reason is the underlying error's text, redacted. Never the raw error.
	Reason string
	cause  error
}

func (e *SentinelConfigError) Error() string {
	return fmt.Sprintf("kubernetes client configuration failed (%s): %s", e.Source, e.Reason)
}

// Unwrap returns the underlying error.
//
// Present so errors.Is/As still work for programmatic handling, while Error()
// stays safe to log. Callers that log with %v or %s get the redacted form.
func (e *SentinelConfigError) Unwrap() error { return e.cause }

// CredentialHints are substrings that indicate credential material in an error
// string. Matched case-insensitively against the raw error before wrapping.
var CredentialHints = []string{
	"token",
	"secret",
	"password",
	"passwd",
	"credential",
	"bearer",
	"authorization",
	"apikey",
	"api_key",
	"privatekey",
	"private_key",
	"ca.crt",
	"client.key",
	"kubeconfig",
}

// RedactError strips credential-shaped substrings from err's text.
//
// It is a last line of defence, not the control. The control is that error text
// is logged at all only in a redacted form; this function exists because an
// upstream library can put a token path into an error and we should not have to
// audit every upstream error string to know our logs are safe.
//
// The replacement is the literal "[REDACTED]", matching internal/scrubber and
// ARCH §6 M1, so a redacted token and a scrubbed token are indistinguishable to a
// reader - which is the point.
// RedactError strips credential material from err's text.
//
// It is a last line of defence, not the control. The control is that error text is
// logged only in a redacted form; this exists because an upstream library can put a
// token into an error and we should not have to audit every upstream string.
//
// It keeps the *name* of the credential and the separator around it, and removes
// only the value: "password: hunter2" becomes "password: [REDACTED]", which still
// says what failed. Removing everything would satisfy the letter of the rule while
// making the log useless, and a log nobody reads is a log nobody trusts.
func RedactError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	for _, hint := range CredentialHints {
		text = redactHint(text, hint)
	}
	return text
}

// redactHint replaces every occurrence of hint, and the value that follows it,
// with [REDACTED].
//
// Two shapes needed handling, both found by a test that failed rather than by
// reading the code:
//
//   - "bearer token abcdef": the word after the hint is *itself* a hint, so a single
//     value scan consumed "token" and left the credential behind.
//   - "password: hunter2" and "api_key=sk-live-1234": the value is separated by a
//     delimiter, so scanning only non-delimiter characters after the hint stopped
//     immediately and leaked the value.
func redactHint(text, hint string) string {
	// The search only ever moves forward.
	//
	// An earlier version restarted from index 0 after each replacement. That is
	// not just slower: when the hint word is preserved (as it is here, so the log
	// still says *which* credential was involved) the same hint is found again,
	// the replacement is applied again, and the string grows without bound. It
	// surfaced as a test-suite timeout rather than as an obvious hang, because the
	// growth is fast enough to look like slow progress.
	from := 0
	for {
		rel := indexFoldFrom(text, hint, from)
		if rel < 0 {
			return text
		}
		index := rel
		head := index + len(hint)
		cursor := head
		// Absorb separators, and any further hint words, before taking the value.
		for {
			for cursor < len(text) && isSeparator(text[cursor]) {
				cursor++
			}
			if cursor >= len(text) {
				break
			}
			wordEnd := cursor
			for wordEnd < len(text) && !isSeparator(text[wordEnd]) {
				wordEnd++
			}
			if isCredentialWord(text[cursor:wordEnd]) {
				cursor = wordEnd
				continue
			}
			break
		}
		if cursor >= len(text) {
			// Only separators after the hint: mask the hint alone.
			text = text[:index] + "[REDACTED]" + text[head:]
			from = index + len("[REDACTED]")
			continue
		}
		valueEnd := cursor
		for valueEnd < len(text) && !isSeparator(text[valueEnd]) {
			valueEnd++
		}
		// Keep the separators so the log still shows the shape of the failure
		// ("password: [REDACTED]"), and keep the hint name for the same reason.
		text = text[:head] + text[head:cursor] + "[REDACTED]" + text[valueEnd:]
		from = head + (cursor - head) + len("[REDACTED]")
	}
}

// isCredentialWord reports whether a bare word is itself one of the hints.
func isCredentialWord(word string) bool {
	trimmed := word
	for len(trimmed) > 0 && isSeparator(trimmed[len(trimmed)-1]) {
		trimmed = trimmed[:len(trimmed)-1]
	}
	for _, hint := range CredentialHints {
		if equalFold(trimmed, hint) {
			return true
		}
	}
	return false
}

// isSeparator reports whether a character can sit between a credential's name and
// its value.
func isSeparator(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"', '\'', '`', '=', ':', ',', ';',
		'(', ')', '{', '}', '[', ']', '/', '\\', '|':
		return true
	}
	return false
}

// indexFoldFrom finds needle in haystack at or after `from`, case-insensitively.
func indexFoldFrom(haystack, needle string, from int) int {
	n := len(needle)
	if n == 0 || n > len(haystack) {
		return -1
	}
	if from < 0 {
		from = 0
	}
	for i := from; i+n <= len(haystack); i++ {
		if equalFold(haystack[i:i+n], needle) {
			return i
		}
	}
	return -1
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// NewClientset builds a read-only client.
//
// Resolution order, and why:
//
//  1. kubeconfigPath non-empty  - an explicit path always wins, because it is a
//     deliberate operator action and must not be silently overridden.
//  2. in-cluster               - rest.InClusterConfig, which reads the mounted
//     service-account token. This is how the Sentinel runs in production.
//  3. $KUBECONFIG              - the standard kubectl convention, so the daemon
//     behaves like every other tool an operator already has open.
//  4. in-cluster again         - a last attempt, so a correctly-mounted pod
//     without a kubeconfig still works. Retrying is cheap and the alternative is
//     an operator staring at "no configuration found" while holding one.
func NewClientset(kubeconfigPath string) (kubernetes.Interface, error) {
	var lastErr error

	if kubeconfigPath != "" {
		client, err := clientsetFromKubeconfig(kubeconfigPath)
		if err == nil {
			return client, nil
		}
		lastErr = &SentinelConfigError{
			Source: "kubeconfig",
			Reason: RedactError(err),
			cause:  err,
		}
		// An explicit path that does not work is a hard error. Falling through to
		// in-cluster would silently use a *different* credential than the operator
		// asked for, which is the kind of surprise that produces a confusing
		// authorisation failure much later.
		return nil, lastErr
	}

	if inClusterAvailable() {
		client, err := clientsetFromInCluster()
		if err == nil {
			return client, nil
		}
		lastErr = &SentinelConfigError{
			Source: "in-cluster",
			Reason: RedactError(err),
			cause:  err,
		}
	}

	if path := os.Getenv("KUBECONFIG"); path != "" {
		client, err := clientsetFromKubeconfig(path)
		if err == nil {
			return client, nil
		}
		if lastErr == nil {
			lastErr = &SentinelConfigError{
				Source: "KUBECONFIG",
				Reason: RedactError(err),
				cause:  err,
			}
		}
	}

	if lastErr == nil {
		if client, err := clientsetFromInCluster(); err == nil {
			return client, nil
		}
	}

	if lastErr == nil {
		lastErr = &SentinelConfigError{
			Source: "none",
			Reason: "no in-cluster service account and no kubeconfig found; " +
				"set KUBECONFIG or pass an explicit path",
		}
	}
	return nil, lastErr
}

func inClusterAvailable() bool {
	// rest.InClusterConfig's own precondition. Checked here so an out-of-cluster
	// process gets the clearer "no kubeconfig" message instead of an error
	// complaining about a missing token file it was never going to have.
	return os.Getenv("KUBERNETES_SERVICE_HOST") != "" && os.Getenv("KUBERNETES_SERVICE_PORT") != ""
}

func clientsetFromInCluster() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

func clientsetFromKubeconfig(path string) (kubernetes.Interface, error) {
	// clientcmd's loader reads and parses the file. It is bounded by the
	// filesystem; there is no context to pass, and AGENTS.md §3.2's rule about
	// bounded blocking calls applies to network calls, which is where
	// WatchUntilSynced and the informer's List/Watch apply their timeouts.
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = path
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// ErrNoConfiguration is returned when no configuration source could be found.
var ErrNoConfiguration = errors.New("no kubernetes configuration available")

// ClientsetOnly reports mutating methods reachable through the read-only facade.
//
// This exists to make ROADMAP 3.1.4 - "confirm no mutating client method is
// reachable from any package" - a mechanical check rather than a reading of the
// source. It checks the facade's exported method set against an exact allow-list,
// so a write is caught whatever it is named - and an added accessor fails the
// build rather than needing a new deny-list entry.
//
// Returns every offending method name rather than a single bool, so a failure
// names the method instead of asserting that some method somewhere is suspect.
func ClientsetOnly() []string {
	return DisallowedFacadeMethods()
}
