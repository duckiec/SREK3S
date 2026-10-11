package scrubber

import (
	"encoding/json"
	"strings"
	"testing"
)

// The loader must validate STRENGTH, not just SHAPE.
//
// Every check that existed before these tests proved a manifest was
// well-formed: known fields, one document, unique IDs, canonical order, all
// eleven rules present, every pattern compiling. None of them proved the
// manifest was the manifest this engine was built to run. Three edits sail
// through every one of those checks and install cleanly, each disarming a rule
// while LoadManifestBytes reports success:
//
//   - multiLine=false on pem_private_key removes it from the M3 cross-line
//     pass, so rule 11 redacts only the BEGIN marker and the block body
//     survives. This is defect D-3, recorded in CONTRIBUTING.md as "the leak
//     was total".
//   - a pattern that compiles but matches nothing installs a rule that never
//     fires.
//   - a template of "${1}${2}${3}" makes ExpandString substitute the captured
//     groups back, so the output is byte-identical to the input while
//     RedactionReport still records a hit: a rule that reports success while
//     redacting nothing.
//
// docs/security-invariants.md states the contract - "There is no
// configuration that disables a rule, redacts nothing, or substitutes a
// different placeholder" - and until the strength check that statement was
// documentation, not a control.
//
// None of these tests call t.Parallel: LoadManifestBytes installs into
// package-global state, so a concurrent load replaces the manifest another
// test is asserting against. strictload_test.go records the same constraint
// for the same reason.

// rewriteRule applies one JSON edit to the shipped manifest, by rule ID.
func rewriteRule(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	raw := strings.Replace(
		string(mustRead(t, "../../deploy/scrubber-configmap.yaml")),
		"    scrubber.json: |\n",
		"",
		1,
	)
	raw = unindentYAMLBlock(raw)
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("decode shipped manifest: %v", err)
	}
	rules := doc["rules"].([]any)
	for _, r := range rules {
		if mutate != nil {
			mutate(r.(map[string]any))
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return out
}

func TestAMultiLineFlipIsRefused(t *testing.T) {
	for _, id := range []RuleID{RulePEMPrivateKey, RuleAWSAccessKeyID} {
		want := multiLineRules[id]
		raw := rewriteRule(t, func(row map[string]any) {
			row["multiLine"] = !want
		})
		err := LoadManifestBytes(raw)
		if err == nil {
			t.Errorf("multiLine=%v on %q loaded; the rule is silently disarmed", !want, id)
			continue
		}
		if !strings.Contains(err.Error(), "multiLine") {
			t.Errorf("the error should name multiLine, got %v", err)
		}
	}
}

func TestAWeakenedPatternIsRefused(t *testing.T) {
	// A pattern that still compiles. This is the edit that matters: it is not
	// a syntax error, so nothing else refuses it.
	for _, id := range []RuleID{RuleBearerToken, RuleUUID, RuleIPv4Address} {
		raw := rewriteRule(t, func(row map[string]any) {
			if row["id"] == string(id) {
				row["pattern"] = "x"
			}
		})
		if err := LoadManifestBytes(raw); err == nil {
			t.Errorf("pattern=\"x\" on %q loaded; the rule never fires", id)
		}
	}
}

func TestARewrittenTemplateIsRefused(t *testing.T) {
	// The edit that is hardest to see: the manifest still loads, the rule still
	// reports a hit, and the output is unchanged. ExpandString substitutes the
	// captured groups back, so ${1}${2}${3} is the identity function.
	for _, id := range []RuleID{RuleBasicAuthURL, RuleGenericSecretKV} {
		raw := rewriteRule(t, func(row map[string]any) {
			if row["id"] == string(id) {
				row["template"] = "${1}${2}${3}"
			}
		})
		if err := LoadManifestBytes(raw); err == nil {
			t.Errorf("template=${1}${2}${3} on %q loaded; it redacts nothing while reporting a hit", id)
		}
	}
}

// The control. Without it the three tests above would pass against a loader
// that rejects every manifest, which is a loader that refuses to load.
func TestTheStrengthChecksDoNotRejectTheShippedManifest(t *testing.T) {
	if err := LoadManifestBytes(rewriteRule(t, nil)); err != nil {
		t.Fatalf("the shipped manifest must load: %v", err)
	}
	if len(Manifest) != 11 {
		t.Fatalf("loaded %d rules, want 11", len(Manifest))
	}
}

// A manifest that diverges in EVERY field at once is still refused. Guards the
// strength checks against a future edit that makes them pass unconditionally.
func TestAManifestDivergingInEveryFieldIsStillRefused(t *testing.T) {
	raw := rewriteRule(t, func(row map[string]any) {
		row["pattern"] = "x"
		row["multiLine"] = !multiLineRules[RuleID(row["id"].(string))]
		row["template"] = "${1}${2}${3}"
	})
	if err := LoadManifestBytes(raw); err == nil {
		t.Fatal("a manifest diverging in pattern, multiLine and template must not load")
	}
}

// An unknown rule ID is refused, and the empty-pattern shape it carried is
// refused with it. Before the order loop rejected non-canonical IDs, an appended
// {"id":"rogue","pattern":""} fell through every check: the two order branches
// ignored it, the three strength comparisons matched it against the zero value
// of a missing map key ("" == "", false == false), and regexp.Compile("")
// succeeded, installing a 12th rule whose empty pattern matches at every
// offset. That rule shreds every line before the canonical rules run, so a
// secret leaks in fragments while the report counts a redaction. Reverting the
// !isCanonical rejection reds this test.
func TestAnUnknownRuleIDIsRefused(t *testing.T) {
	restore := captureGlobals()
	defer restore()

	raw := mustRead(t, "testdata/scrubber.json")
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("decode shipped manifest: %v", err)
	}
	rules, _ := doc["rules"].([]any)
	rules = append(rules, map[string]any{
		"id": "rogue_extra", "pattern": "", "multiLine": false, "template": "",
	})
	doc["rules"] = rules
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if err := LoadManifestBytes(out); err == nil {
		t.Fatal("a rule whose ID is not one of the 11 must not load")
	}
	if len(Manifest) != 11 {
		t.Errorf("Manifest has %d rules, want 11; the rogue rule must not persist", len(Manifest))
	}
}

// The test-isolation guard.
//
// LoadManifestBytes installs into package-global state. Before captureGlobals,
// a loader test left Manifest pointing at whatever it loaded, and the corpus
// tests - which run after every sequential test - validated that. They saw the
// correct ruleset only because TestTheShippedManifestStillLoads happened to run
// last among the sequential tests and reload the pristine ConfigMap. Reorder the
// files, rename that test, or run the package with -run and the corpus silently
// validates the wrong ruleset.
//
// This asserts the restore mechanism does what every loader test now relies
// on: whatever a test installed, the compiled table is back when it returns.
func TestCaptureGlobalsRestoresWhatALoaderTestInstalled(t *testing.T) {
	compiled := Manifest
	restore := captureGlobals()

	// Install something wrong, the way a loader test does.
	Manifest = nil
	ruleTemplates = map[RuleID]string{}

	restore()

	if len(Manifest) != len(compiled) {
		t.Errorf("Manifest has %d rules after restore, want %d", len(Manifest), len(compiled))
	}
	if _, ok := ruleTemplates[RuleBasicAuthURL]; !ok {
		t.Error("ruleTemplates lost basic_auth_url after restore")
	}
}

// The ordering hazard itself, stated as a property rather than left to luck.
//
// The corpus tests are t.Parallel and therefore run after every sequential
// test in the package. If a loader test leaves a disarmed Manifest behind, the
// corpus validates that disarmed Manifest. This test runs a disarming load and
// then asserts the compiled table is intact - which is what makes the corpus
// trustworthy regardless of which loader tests ran before it or in what order.
func TestADisarmingLoadDoesNotReachTheCorpus(t *testing.T) {
	// Install a manifest whose pem_private_key is disarmed, the D-3 shape.
	raw := rewriteRule(t, func(row map[string]any) {
		if row["id"] == string(RulePEMPrivateKey) {
			row["multiLine"] = false
		}
	})

	restore := captureGlobals()
	defer restore()
	if err := LoadManifestBytes(raw); err == nil {
		t.Fatal("precondition: the disarmed manifest must be refused")
	}

	// The compiled table must still carry the cross-line rule. This is the
	// assertion the corpus tests would be making if they were not protected by
	// the sequential/parallel ordering.
	multi := multiLineManifest()
	var found bool
	for _, r := range multi {
		if r.ID == RulePEMPrivateKey {
			found = true
		}
	}
	if !found {
		t.Error("pem_private_key is absent from the M3 cross-line pass; D-3 is present")
	}
}
