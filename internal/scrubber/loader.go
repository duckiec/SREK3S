package scrubber

import (
	"encoding/json"
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
// omitted canonical rule, or an invalid regex all return an error. The caller
// panics on a non-nil error; there is no partial install, no skip-and-
// continue, and no degraded scrubber. The file read happens in the caller so
// this package stays free of os imports (ROADMAP 1.4.10).
func LoadManifestBytes(raw []byte) error {
	var mf ManifestFile
	if err := json.Unmarshal(raw, &mf); err != nil {
		return fmt.Errorf("scrubber: parse manifest: %w", err)
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
