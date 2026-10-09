// A rule manifest is configuration, and configuration that silently loses a key
// is worse than configuration that refuses to load.
//
// json.Unmarshal ignores unknown keys, so a ConfigMap edited to misspell `pattern`
// as `regex` produced a rule whose Pattern was "". The empty pattern compiles,
// installs, and matches at every position - one typo disarmed one of the eleven
// rules while LoadManifestBytes reported success and the docstring claimed "no
// partial install, no skip-and-continue, and no degraded scrubber".
//
// None of these tests call t.Parallel: LoadManifestBytes installs into
// package-global state, so a concurrent load replaces the manifest another test is
// asserting against. Under -race that is a real data race, and loader_test.go has
// never used t.Parallel for the same reason.

package scrubber

import (
	"regexp"
	"strings"
	"testing"
)

func loadWith(t *testing.T, mutate func(string) string) error {
	t.Helper()
	raw := strings.Replace(
		string(mustRead(t, "../../deploy/scrubber-configmap.yaml")),
		"    scrubber.json: |\n",
		"",
		1,
	)
	raw = unindentYAMLBlock(raw)
	return LoadManifestBytes([]byte(mutate(raw)))
}

// mustRead and unindentYAMLBlock read the shipped ConfigMap and lift its
// embedded JSON document, so these tests run against the file that ships rather
// than against a transcription that can drift from it.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	return []byte(readFile(t, path))
}

func TestTheShippedManifestStillLoads(t *testing.T) {
	// The control. Without it every test below would pass on a loader that rejects
	// everything.
	if err := loadWith(t, func(s string) string { return s }); err != nil {
		t.Fatalf("the shipped manifest must load: %v", err)
	}
}

func TestAMisspelledPatternKeyIsRefused(t *testing.T) {
	err := loadWith(t, func(s string) string {
		// The jwt rule is the one whose key this rewrites, chosen because it is
		// the only rule whose pattern opens with a plain `\b`.
		out := strings.Replace(s, `"pattern": "\\beyJ`, `"regex": "\\beyJ`, 1)
		if out == s {
			t.Fatal(`could not find the jwt rule's pattern key to misspell`)
		}
		return out
	})
	if err == nil {
		t.Fatal(`a rule whose "pattern" key is spelled "regex" must not load`)
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("the error should name the unknown field, got %v", err)
	}
}

func TestAnUnknownTopLevelKeyIsRefused(t *testing.T) {
	err := loadWith(t, func(s string) string {
		return strings.Replace(s, `"version": "1",`, `"version": "1", "extra": true,`, 1)
	})
	if err == nil {
		t.Fatal("an unknown top-level key must not load")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("the error should name the unknown field, got %v", err)
	}
}

func TestASecondJSONDocumentIsRefused(t *testing.T) {
	err := loadWith(t, func(s string) string { return s + s })
	if err == nil {
		t.Fatal("a manifest carrying two documents must not load the first and ignore the rest")
	}
	if !strings.Contains(err.Error(), "more than one JSON document") {
		t.Errorf("the error should name the problem, got %v", err)
	}
}

// The defect's actual shape, end to end: an empty pattern compiles, so the rule
// installs and stops matching anything. Refusing the manifest is the only outcome
// that keeps the eleven rules armed.
func TestAnEmptyPatternCannotReachTheManifest(t *testing.T) {
	raw := `{"version":"1","rules":[{"id":"pem_private_key","regex":"x","multiLine":true}]}`
	if _, err := decodeManifest([]byte(raw)); err == nil {
		t.Fatal("decodeManifest must refuse a rule with no pattern key")
	}
	// And the disarmed rule the permissive decoder produced, for the record: an
	// empty pattern compiles, so the rule installed and matched nothing.
	rule := Rule{ID: RulePEMPrivateKey, RE: regexp.MustCompile("")}
	t.Logf("the disarmed rule the permissive decoder accepted: id=%s pattern=%q", rule.ID, rule.RE.String())
	if !rule.RE.MatchString("anything at all") {
		t.Fatal("precondition: an empty pattern matches everything, which is why it must never compile")
	}
}

func TestTruncatedJSONIsStillRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"truncated":     `{"version":"1","rules":[{"id":"pem_private_key"`,
		"not json":      `version: 1`,
		"empty":         ``,
		"null":          `null`,
		"array":         `[]`,
		"rules not arr": `{"version":"1","rules":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := LoadManifestBytes([]byte(raw)); err == nil {
				t.Fatalf("%s must not load", name)
			}
		})
	}
}
