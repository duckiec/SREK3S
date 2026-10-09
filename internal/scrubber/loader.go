package scrubber

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// ManifestFile is the on-disk schema for a scrubber rule manifest.
//
// The shape is deliberately a plain list, not a map keyed by rule ID: the order
// is normative (CONTRIBUTING.md §5), and a JSON object would make the order
// undefined. Keeping it a list preserves the normative order through every
// load.
type ManifestFile struct {
	Version string `json:"version"`
	Rules   []struct {
		ID        RuleID `json:"id"`
		Pattern   string `json:"pattern"`
		MultiLine bool   `json:"multiLine"`
		Template  string `json:"template"`
	} `json:"rules"`
}

// LoadManifestBytes parses, compiles and installs a rule manifest exactly once.
//
// Fail-fast: a schema violation, an unknown rule ID, an out-of-order table, an
// omitted canonical rule, or an invalid regex all return an error. There is no
// partial install, no skip-and-continue, and no degraded scrubber. The file read
// happens in the caller so this package stays free of os imports (ROADMAP
// 1.4.10).
//
// THE CALLER DOES NOT PANIC. This comment used to say it did, and it was wrong:
// cmd/sentinel/main.go wraps the error and returns it, so the process exits 1
// before the watcher starts. The distinction is load-bearing rather than
// stylistic. A panic under a crash-looping supervisor is restarted into the same
// failure and reported as an unstable crash loop, while exit 1 reads as the
// configuration error it is - a malformed scrubber manifest, which is a
// deployment mistake and not a defect to be retried. A reader who believed the
// old comment would expect a stack trace and misread its absence as a bug.
//
// main.go also does not recover, so there is no path that turns this into a
// partial install either way.
// decodeManifest parses the rule manifest, refusing anything the schema does not
// describe.
//
// json.Unmarshal ignores unknown keys, so a ConfigMap edited to misspell `pattern`
// as `regex` produced a rule whose Pattern was the empty string. The empty pattern
// compiles, installs, and matches at every position - so one typo silently
// disarmed one of the eleven rules while the report said the manifest had loaded.
// Measured: rule "pem_private_key" compiled to an EMPTY pattern, and a planted
// credential passed through unmasked.
//
// That contradicts the docstring above, which claims a schema violation returns an
// error and that there is "no partial install, no skip-and-continue, and no degraded
// scrubber". With the decoder strict, the claim is true of unknown fields too.
//
// DisallowUnknownFields is deliberately not paired with a trailing-comma or a
// case-insensitive key fallback: the manifest is generated from a Go struct and
// checked into deploy/scrubber-configmap.yaml, so there is no reason to accept a
// spelling the code does not produce.
func decodeManifest(raw []byte) (ManifestFile, error) {
	var mf ManifestFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&mf); err != nil {
		return ManifestFile{}, fmt.Errorf("scrubber: parse manifest: %w", err)
	}
	// A second document in the same stream is not part of the contract. Without
	// this check the trailing bytes are ignored, so `{...}{...}` loads the first
	// object and discards the rest - the same class of surprise as an unknown key.
	if dec.More() {
		return ManifestFile{}, errors.New(
			"scrubber: manifest carries more than one JSON document; the loader " +
				"accepts exactly one",
		)
	}
	return mf, nil
}

func LoadManifestBytes(raw []byte) error {
	mf, err := decodeManifest(raw)
	if err != nil {
		return err
	}
	if len(mf.Rules) == 0 {
		return fmt.Errorf("scrubber: manifest has no rules")
	}

	seen := make(map[RuleID]bool)
	canonicalAt := 0
	for _, r := range mf.Rules {
		if seen[r.ID] {
			return fmt.Errorf("scrubber: manifest has duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if canonicalAt < len(manifestOrder) && r.ID == manifestOrder[canonicalAt] {
			canonicalAt++
		} else if isCanonical(r.ID) {
			return fmt.Errorf("scrubber: manifest places rule %q out of normative order (CONTRIBUTING.md §5)", r.ID)
		}
	}
	if canonicalAt != len(manifestOrder) {
		return fmt.Errorf("scrubber: manifest omits one or more of the 11 CONTRIBUTING.md §5 rules")
	}
	rules := make([]Rule, 0, len(mf.Rules))
	templates := make(map[RuleID]string)
	for _, r := range mf.Rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("scrubber: manifest rule %q does not compile: %w", r.ID, err)
		}
		rules = append(rules, Rule{ID: r.ID, RE: re, MultiLine: r.MultiLine})
		if r.Template != "" {
			templates[r.ID] = r.Template
		}
	}

	Manifest = rules
	ruleTemplates = templates
	return nil
}

func isCanonical(id RuleID) bool {
	for _, c := range manifestOrder {
		if c == id {
			return true
		}
	}
	return false
}
