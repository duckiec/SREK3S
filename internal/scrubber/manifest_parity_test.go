package scrubber

import (
	"encoding/json"
	"os"
	"testing"
)

// The five shipped copies of the eleven rules must agree with the compiled table.
//
// The rules exist in five places: the Go source (rulePatterns, multiLineRules,
// ruleTemplates), the embedded default (internal/scrubber/default_manifest.json),
// the test fixture (internal/scrubber/testdata/scrubber.json), the deployable
// manifest (deploy/scrubber.json), the Helm chart's copy
// (deploy/helm/srek3s/files/scrubber.json), and the ConfigMap the Sentinel
// actually loads (deploy/scrubber-configmap.yaml).
//
// Before this test, exactly one assertion connected two of those copies:
// test_helm_chart.py::test_render_matches_kustomize_base compares the chart's
// copy against deploy/scrubber.json. Nothing connected either of those to the
// compiled table, and nothing connected the ConfigMap - the copy the running
// Sentinel loads - to anything.
//
// That gap is the same class as the loader's shape-not-strength hole: a copy
// that drifts is not caught by any gate that runs. If the ConfigMap's patterns
// were edited to something weaker, the Sentinel would boot with a disarmed
// scrubber and every test that loads the ConfigMap would pass, because they
// would all be validating the same weakened rules.
//
// The test loads each copy through the real loader and asserts the installed
// table is byte-identical to the compiled one. It also asserts the copies are
// byte-identical to each other, so a future edit to one copy fails here rather
// than at deploy time.
//
// None of these tests call t.Parallel: LoadManifestBytes installs into
// package-global state, so a concurrent load replaces the manifest another
// test is asserting against. strictload_test.go records the same constraint
// for the same reason.

// manifestCopy is one shipped copy of the rule table.
type manifestCopy struct {
	name string
	path string
}

var manifestCopies = []manifestCopy{
	{"embedded default", "default_manifest.json"},
	{"test fixture", "testdata/scrubber.json"},
	{"deploy manifest", "../../deploy/scrubber.json"},
	{"helm chart", "../../deploy/helm/srek3s/files/scrubber.json"},
}

func TestEveryShippedManifestCopyMatchesTheCompiledOne(t *testing.T) {
	compiled := Manifest
	compiledTemplates := ruleTemplates
	restore := captureGlobals()
	defer restore()

	for _, copy := range manifestCopies {
		raw, err := os.ReadFile(copy.path)
		if err != nil {
			t.Fatalf("read %s: %v", copy.path, err)
		}
		if err := LoadManifestBytes(raw); err != nil {
			t.Fatalf("load %s: %v", copy.path, err)
		}

		if len(Manifest) != len(compiled) {
			t.Fatalf("%s installed %d rules, want %d", copy.name, len(Manifest), len(compiled))
		}
		for i, r := range Manifest {
			if r.ID != compiled[i].ID {
				t.Errorf("%s rule %d id = %q, want %q", copy.name, i, r.ID, compiled[i].ID)
			}
			if r.RE.String() != compiled[i].RE.String() {
				t.Errorf("%s rule %q pattern = %q, want %q",
					copy.name, r.ID, r.RE.String(), compiled[i].RE.String())
			}
			if r.MultiLine != compiled[i].MultiLine {
				t.Errorf("%s rule %q multiLine = %v, want %v",
					copy.name, r.ID, r.MultiLine, compiled[i].MultiLine)
			}
		}
		for id, tmpl := range compiledTemplates {
			if got := ruleTemplates[id]; got != tmpl {
				t.Errorf("%s template for %q = %q, want %q", copy.name, id, got, tmpl)
			}
		}
	}
}

// The ConfigMap is the copy the running Sentinel loads, so it gets its own
// assertion rather than sharing the table-driven one above: it is embedded in
// YAML rather than being a standalone JSON file, and the embedding is itself a
// place drift can hide.
func TestTheConfigMapCopyMatchesTheCompiledOne(t *testing.T) {
	compiled := Manifest
	restore := captureGlobals()
	defer restore()

	if err := LoadManifestBytes(rewriteRule(t, nil)); err != nil {
		t.Fatalf("the shipped ConfigMap must load: %v", err)
	}
	if len(Manifest) != len(compiled) {
		t.Fatalf("ConfigMap installed %d rules, want %d", len(Manifest), len(compiled))
	}
	for i, r := range Manifest {
		if r.ID != compiled[i].ID {
			t.Errorf("ConfigMap rule %d id = %q, want %q", i, r.ID, compiled[i].ID)
		}
		if r.RE.String() != compiled[i].RE.String() {
			t.Errorf("ConfigMap rule %q pattern = %q, want %q",
				r.ID, r.RE.String(), compiled[i].RE.String())
		}
		if r.MultiLine != compiled[i].MultiLine {
			t.Errorf("ConfigMap rule %q multiLine = %v, want %v",
				r.ID, r.MultiLine, compiled[i].MultiLine)
		}
	}
}

// The copies must agree with EACH OTHER, not only with the compiled table. Two
// copies can both differ from the compiled table in the same way - if the
// compiled table itself were edited - and the assertions above would still
// pass. This catches the case where one copy is edited and the others are not.
func TestTheShippedCopiesAgreeWithEachOther(t *testing.T) {
	var reference []byte
	var referenceName string
	for _, copy := range manifestCopies {
		raw, err := os.ReadFile(copy.path)
		if err != nil {
			t.Fatalf("read %s: %v", copy.path, err)
		}
		if reference == nil {
			reference = raw
			referenceName = copy.name
			continue
		}
		if string(raw) != string(reference) {
			t.Errorf("%s differs from %s", copy.name, referenceName)
		}
	}
}

// A drift in one copy is refused by the loader, not merely reported. This is
// the end-to-end form of the strength check: the ConfigMap is the attack
// surface, and a weakened ConfigMap must not reach the running Sentinel.
func TestAWeakenedConfigMapCannotReachTheSentinel(t *testing.T) {
	restore := captureGlobals()
	defer restore()

	// The exact edit an operator or an attacker with ConfigMap write access
	// would make: one boolean, flipped, on the one rule whose cross-line
	// capability is load-bearing.
	raw := rewriteRule(t, func(row map[string]any) {
		if row["id"] == string(RulePEMPrivateKey) {
			row["multiLine"] = false
		}
	})

	if err := LoadManifestBytes(raw); err == nil {
		t.Fatal("a ConfigMap that disarms pem_private_key must not load")
	}

	// And the compiled table is untouched, so the corpus tests that run after
	// this one are still validating the real ruleset.
	if len(Manifest) != 11 {
		t.Errorf("Manifest has %d rules, want 11", len(Manifest))
	}
}

// The version string must agree across every copy. A copy with a stale version
// is a file that could be mistaken for the current table by a reader, even when
// its rules still match. Full byte identity is asserted separately by
// TestTheShippedCopiesAgreeWithEachOther, so this names version only.
func TestTheShippedCopiesCarryTheSameVersion(t *testing.T) {
	docs := make(map[string]map[string]any)
	for _, copy := range manifestCopies {
		raw, err := os.ReadFile(copy.path)
		if err != nil {
			t.Fatalf("read %s: %v", copy.path, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("decode %s: %v", copy.path, err)
		}
		docs[copy.name] = doc
	}

	names := make([]string, 0, len(docs))
	for name := range docs {
		names = append(names, name)
	}
	for _, name := range names {
		other := docs[names[0]]
		if name == names[0] {
			continue
		}
		if docs[name]["version"] != other["version"] {
			t.Errorf("%s version = %v, want %v", name, docs[name]["version"], other["version"])
		}
	}
}
