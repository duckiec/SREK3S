package scrubber

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func writeTemp(t *testing.T, body string) string { // legacy helper
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "scrubber.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadManifestFromFileLoads the normative fixture and verifies it reproduces
// the embedded default ruleset: same IDs, same order, same templates. This is
// the corpus-gate bridge - a bad fixture fails here before the corpus runs.
// captureGlobals snapshots the package-global rule tables and returns a
// function that restores them.
//
// LoadManifestBytes installs into package-global state, so a test that loads a
// manifest leaves Manifest and ruleTemplates pointing at whatever it loaded.
// Without a restore, every later test in the package - including the t.Parallel
// corpus tests, which run after all the sequential loader tests - validates
// whatever the LAST load happened to install. That is not a theoretical
// hazard: the corpus tests pass against a disarmed manifest today only because
// TestTheShippedManifestStillLoads runs afterwards and reloads the pristine
// ConfigMap. Reorder the files, rename that test, or run with -run and the
// corpus silently validates the wrong ruleset.
//
//nolint:gochecknoglobals // Test helper for package-global state.
func captureGlobals() func() {
	manifest := Manifest
	templates := ruleTemplates
	return func() {
		Manifest = manifest
		ruleTemplates = templates
	}
}

func TestLoadManifestFromFileLoads(t *testing.T) {
	t.Cleanup(captureGlobals())
	before := Manifest
	raw, err := os.ReadFile("testdata/scrubber.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := LoadManifestBytes(raw); err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	if len(Manifest) != len(before) {
		t.Errorf("loaded %d rules, want %d", len(Manifest), len(before))
	}
	for i, r := range Manifest {
		if r.ID != before[i].ID {
			t.Errorf("rule %d id = %q, want %q", i, r.ID, before[i].ID)
		}
		if _, err := regexp.Compile(r.RE.String()); err != nil {
			t.Errorf("rule %q does not recompile: %v", r.ID, err)
		}
	}
	if got := ruleByIDOrBust(t, RuleBasicAuthURL).templateFor(); got != "${1}"+RedactionSentinel+"${3}" {
		t.Errorf("basic_auth_url template = %q", got)
	}
	if got := ruleByIDOrBust(t, RuleGenericSecretKV).templateFor(); got != "${1}"+RedactionSentinel+"${3}" {
		t.Errorf("generic_secret_kv template = %q", got)
	}
}

func ruleByIDOrBust(t *testing.T, id RuleID) Rule {
	t.Helper()
	r, ok := ruleByID(id)
	if !ok {
		t.Fatalf("rule %q missing", id)
	}
	return r
}

// TestLoadManifestFromFileFailsClosed proves a malformed manifest panics the
// scrubber rather than booting with a bypassed one. Each case must error.
func TestLoadManifestFromFileFailsClosed(t *testing.T) {
	t.Cleanup(captureGlobals())
	cases := map[string]string{
		"missing file":      "\n",
		"not json":          "this is not json\n",
		"no rules":          `{"version":"1","rules":[]}`,
		"bad regex":         `{"version":"1","rules":[{"id":"pem_private_key","pattern":"(["}]}`,
		"wrong order":       `{"version":"1","rules":[{"id":"aws_access_key_id","pattern":"x"},{"id":"pem_private_key","pattern":"y"}]}`,
		"missing canonical": `{"version":"1","rules":[{"id":"custom","pattern":"x"}]}`,
		"duplicate id":      `{"version":"1","rules":[{"id":"uuid","pattern":"x"},{"id":"uuid","pattern":"y"}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := LoadManifestBytes([]byte(body)); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}
