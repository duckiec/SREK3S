package scrubber

import (
	"fmt"
	"regexp"
)

// RuleID identifies a masking rule from the CONTRIBUTING.md §5 manifest.
//
// It is a typed string rather than a bare int so that an accounting entry cannot
// silently refer to the wrong rule, and so the report is self-describing in logs.
type RuleID string

// The eleven rule IDs of the normative manifest. The set and the order are
// fixed by CONTRIBUTING.md §5 and asserted by TestManifestMatchesSpecification.
const (
	RulePEMPrivateKey     RuleID = "pem_private_key"
	RuleAWSAccessKeyID    RuleID = "aws_access_key_id"
	RuleAWSSecretKey      RuleID = "aws_secret_access_key"
	RuleJWT               RuleID = "jwt"
	RuleBearerToken       RuleID = "bearer_token"
	RuleBasicAuthURL      RuleID = "basic_auth_url"
	RuleGenericSecretKV   RuleID = "generic_secret_kv"
	RuleUUID              RuleID = "uuid"
	RuleIPv4Address       RuleID = "ipv4_address"
	RuleK8sSecretMount    RuleID = "k8s_secret_mount"
	RulePrivateKeyPEMBody RuleID = "private_key_pem_body"
)

// manifestOrder is the evaluation order required by CONTRIBUTING.md §5.
//
// Order is normative, not incidental. Structural patterns (PEM blocks, JWTs,
// URIs) run before the generic key=value pattern so that a broad rule cannot
// re-wrap or partially unmask a span an earlier rule already redacted.
var manifestOrder = []RuleID{
	RulePEMPrivateKey,
	RuleAWSAccessKeyID,
	RuleAWSSecretKey,
	RuleJWT,
	RuleBearerToken,
	RuleBasicAuthURL,
	RuleGenericSecretKV,
	RuleUUID,
	RuleIPv4Address,
	RuleK8sSecretMount,
	RulePrivateKeyPEMBody,
}

// Rule is one compiled entry of the manifest.
//
// Every rule replaces its match with RedactionSentinel, so the package holds a
// single unconfigurable masking token (CONTRIBUTING.md §5.1 M1).
type Rule struct {
	ID RuleID
	RE *regexp.Regexp

	// MultiLine marks a rule whose match may span a newline. Only these rules
	// take part in the CONTRIBUTING.md §5.1 M3 cross-line re-scan, which is what keeps that
	// pass from re-running all eleven patterns over the whole joined batch.
	//
	// The flag is not a guess. Each value is asserted by
	// TestMultiLineFlagMatchesCapability, which probes the compiled pattern
	// with inputs whose only distinguishing feature is an embedded newline. A
	// flag set optimistically would silently reintroduce D-3, where a
	// single-line fallback rule redacted a BEGIN marker and left the block body
	// exposed.
	MultiLine bool
}

// Manifest is the compiled-once rule set, in normative order.
//
// It is built in init() from the patterns below. Compilation failure panics
// with the offending rule ID: a silently skipped rule is a security defect
// (ROADMAP 1.1.5), not a warning.
var Manifest []Rule

// rulePatterns maps each rule ID to its regex, transcribed verbatim from the
// CONTRIBUTING.md §5 manifest table.
//
//nolint:gochecknoglobals // Immutable source of truth, consumed once at init.
var rulePatterns = map[RuleID]string{
	RulePEMPrivateKey: `-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----`,

	RuleAWSAccessKeyID: `\b((A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b`,

	RuleAWSSecretKey: `(?i)aws(.{0,20})?(secret|private)(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`,

	RuleJWT: `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`,

	RuleBearerToken: `(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,}=*`,

	// Rule 6, amended per §5.3: only the password is replaced. Group 1 keeps
	// scheme://user: and group 3 keeps @host, so the endpoint topology that an
	// RCA depends on survives.
	RuleBasicAuthURL: `(?i)([a-z][a-z0-9+.-]*:\/\/[^:\s\/]+:)([^@\s\/]+)(@[^\s\/]+)`,

	// Rule 7, amended per §5.6 to fix the unquoted AWS secret access key.
	//
	// `secret(?:[_-]access)?[_-]?key` is listed *before* the bare `secret`
	// alternative so the longest match wins without relying on backtracking, and so
	// the alternation reads longest-first as the rest of the pattern already does.
	//
	// Before this, `secret_access_key` matched nothing: rule 3 is anchored on
	// quotes around the 40-character value, and rule 7's alternation contained
	// `secret[_-]?key`, which does not occur inside `secret_access_key`. So the
	// unquoted form - which is how an env dump or a `key=value` log line carries
	// it - passed the whole 11-rule pipeline unmasked.
	// Rule 7, amended per §5.4 to fix D-1.
	//
	// Three changes, each fixing a distinct leak:
	//   - `["']?` between the key and the separator, so the JSON form
	//     {"password":"hunter2"} matches. Previously a quote defeated the rule.
	//   - The key is prefixed with `[\w-]{0,20}` and the alternation is made
	//     non-capturing, so multi-word keys match. `\b` alone failed on
	//     auth_token because `_` is a word character and so no boundary existed
	//     between the segments.
	//   - The key and the trailing quote are captured, so only the value is
	//     replaced. Without this the surrounding JSON was destroyed along with
	//     the secret.
	//
	// The value class deliberately EXCLUDES a newline. This is not incidental:
	// when the value class admitted \n, the D-5 cross-line pass applied this
	// rule to the whole joined batch first, where a single match swallowed every
	// following line, collapsing a 128-line batch to one line and masking only
	// one rule. Excluding \n makes the rule single-line, which confines the M3
	// pass to pem_private_key and restores both correctness and throughput.
	// The cost is that a key=value secret split across a newline is not caught
	// by M3; see the narrow M3 scope note in CONTRIBUTING.md §5.5.
	RuleGenericSecretKV: `(?i)(\b[\w-]{0,20}(?:api[_-]?key|secret(?:[_-]access)?[_-]?key|secret|token|access[_-]?token|refresh[_-]?token|password|passwd|pwd|passphrase|client[_-]?secret|private[_-]?key|authorization|auth)["']?\s*[:=]\s*["']?)(?P<value>[^"',;}\n]{4,})(["']?)`,

	RuleUUID: `\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`,

	RuleIPv4Address: `\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b`,

	// Rule 10, amended per §5.4 to fix D-2. The original matched only when the
	// namespace preceded the token, whereas the canonical log form is
	// "…/serviceaccount/token for kube-system". Both orders are now accepted via
	// alternation, with the gap bounded to 80 non-newline characters so the rule
	// cannot run across unrelated lines.
	RuleK8sSecretMount: `(?i)\b(?:kube-system|kube-node-lease)\b[^\n]{0,80}(?:token|secret|ca\.crt)|(?i)(?:token|secret|ca\.crt)[^\n]{0,80}\b(?:kube-system|kube-node-lease)\b`,

	RulePrivateKeyPEMBody: `(?i)-----BEGIN[A-Z ]*PRIVATE[A-Z ]*-----`,
}

// multiLineRules records which rules may match a span containing a newline, and
// therefore which take part in the M3 cross-line re-scan (defect D-5).
//
// Derived by probing each compiled pattern with newline-bearing inputs, not by
// inspection. Only pem_private_key qualifies, so the cross-line pass runs one
// pattern instead of eleven.
//
//nolint:gochecknoglobals // Immutable, read-only after init.
var multiLineRules = map[RuleID]bool{
	RulePEMPrivateKey: true, // [\s\S]*? spans lines by construction
}

// ruleTemplates holds the replacement for rules whose span is not simply
// wholly replaced. Any rule absent from this map replaces its entire match with
// RedactionSentinel.
//
//nolint:gochecknoglobals // Immutable, read-only after init.
var ruleTemplates = map[RuleID]string{
	// §5.3: keep scheme, username, @, host and port; redact the password.
	RuleBasicAuthURL: `${1}` + RedactionSentinel + `${3}`,

	// §5.4: keep the key and the closing quote, replace only the value. This is
	// what allows {"password":"hunter2"} to become {"password":"[REDACTED]"}
	// instead of destroying the surrounding JSON structure.
	RuleGenericSecretKV: `${1}` + RedactionSentinel + `${3}`,
}

// canonicalTemplates aliases the init-time ruleTemplates map. LoadManifestBytes
// REASSIGNS ruleTemplates (it never mutates the map in place), so this variable
// keeps pointing at the compiled table's templates after a load. The loader
// validates a manifest's template against this, so a ConfigMap that rewrites a
// template cannot install a rule that reports a hit while redacting nothing.
//
//nolint:gochecknoglobals // Immutable, read-only after init.
var canonicalTemplates = ruleTemplates

func init() {
	Manifest = make([]Rule, 0, len(manifestOrder))
	for _, id := range manifestOrder {
		pattern, ok := rulePatterns[id]
		if !ok {
			panic(fmt.Sprintf("scrubber: rule %q is in the manifest order but has no pattern", id))
		}
		Manifest = append(Manifest, Rule{
			ID:        id,
			RE:        regexp.MustCompile(pattern),
			MultiLine: multiLineRules[id],
		})
	}
}

// multiLineManifest returns only the rules whose match may span a newline, in
// normative order. This is the rule set for the M3 cross-line pass.
func multiLineManifest() []Rule {
	out := make([]Rule, 0, len(multiLineRules))
	for _, r := range Manifest {
		if r.MultiLine {
			out = append(out, r)
		}
	}
	return out
}

// templateFor returns the replacement string for a rule.
func (r Rule) templateFor() string {
	if t, ok := ruleTemplates[r.ID]; ok {
		return t
	}
	return RedactionSentinel
}

// ruleByID returns the manifest entry for an ID.
func ruleByID(id RuleID) (Rule, bool) {
	for _, r := range Manifest {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}
