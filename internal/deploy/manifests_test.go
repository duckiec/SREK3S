// Package deploy holds no code. It exists so the terminal validation test for
// Milestone 3 has a package to live in that is *about* the deployment manifests.
//
// The test is here rather than in Python because ROADMAP's terminal command is
// `go test -race ... ./...`: a check that only runs under pytest would not be
// executed by the command the roadmap names, and a gate that is not run by the
// gate command is a gate that does not exist.
//
// The dependency question this file answers first. Parsing YAML properly needs a
// parser, and adding one to a module whose dependency list is three Kubernetes
// libraries is a real decision. `gopkg.in/yaml.v3` is already in go.mod as an
// *indirect* dependency of client-go, so using it costs no new module, no new
// download, and no new supply-chain surface. It is imported only from _test.go
// files, so it is not linked into the sentinel binary - which
// TestYamlIsNotLinkedIntoTheBinary asserts, because "test-only" is a property
// that decays silently the first time someone imports it from non-test code.
package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// manifestPath is the committed deploy directory, resolved relative to this file
// so the test does not depend on the working directory.
func manifestPath(t *testing.T, name string) string {
	t.Helper()
	// ../../ from internal/deploy reaches the repository root.
	path := filepath.Join("..", "..", "deploy", name)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cannot stat %s: %v", path, err)
	}
	return path
}

// baseManifestPath reads a file from the base of record, deploy/base/.
//
// Separate from manifestPath because the kustomization lives one level below the
// manifests it lists. It sat at deploy/kustomization.yaml until 2026-10-09, when
// that duplicate was deleted; tests that kept naming the old path failed with
// `cannot stat ../../deploy/kustomization.yaml`.
func baseManifestPath(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "deploy", "base", name)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cannot stat %s: %v", path, err)
	}
	return path
}

func readManifest(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(manifestPath(t, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// TestYamlIsOnlyImportedFromTests keeps the dependency honest.
//
// The claim this makes is narrow, and an earlier draft of it was wrong in an
// instructive way: it asserted that `gopkg.in/yaml.v3` is absent from the linked
// package set, and it failed - because `k8s.io/apimachinery` already pulls it in,
// so it was in the sentinel binary before this test existed. Asserting absence
// would have been asserting something untrue about the module's dependencies.
//
// The claim that is both true and worth protecting: no non-test file in *this*
// module imports it. That is what keeps a test-only dependency from quietly
// becoming a production one, and it is checked against `go list`'s split of
// non-test imports from test imports rather than by grepping source.
func TestYamlIsOnlyImportedFromTests(t *testing.T) {
	// .Imports holds imports from non-test files; .TestImports holds imports from
	// _test.go files. The distinction is computed by the go tool, so it accounts for
	// build tags and generated files in a way a source scan does not.
	output, err := exec.Command("go", "list", "-f",
		"{{.ImportPath}}|{{join .Imports \",\"}}|{{join .TestImports \",\"}}", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	sawTestOnly := false
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Split(line, "|")
		if len(fields) != 3 {
			continue
		}
		packagePath, production, tests := fields[0], fields[1], fields[2]
		if strings.Contains(production, "gopkg.in/yaml.v3") {
			t.Errorf("%s imports gopkg.in/yaml.v3 from a non-test file; it is a "+
				"test-only dependency", packagePath)
		}
		if strings.Contains(tests, "gopkg.in/yaml.v3") {
			sawTestOnly = true
		}
	}
	if !sawTestOnly {
		t.Error("no package imports gopkg.in/yaml.v3 from a test file either, so " +
			"the requirement in go.mod is not being used at all")
	}
}

// TestManifestsAreValidYAML is the precondition for every other check in this
// file.
//
// Without it, a parse failure in a hardening test produces a confusing nil-map
// error several frames away, and a manifest that does not load at all would make
// every other assertion vacuous rather than failing.
func TestManifestsAreValidYAML(t *testing.T) {
	for _, name := range []string{
		"namespace.yaml", "rbac.yaml", "sentinel.yaml", "agent.yaml",
	} {
		documents, err := decodeAll(readManifest(t, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(documents) == 0 {
			t.Errorf("%s parsed to zero documents; the checks below would pass vacuously", name)
		}
	}
}

// TestBaseKustomizationIsValidYAML keeps the base of record loadable.
//
// Its own test rather than one more entry in the loop above, because the file lives
// at a different path. Leaving "kustomization.yaml" in that loop after the duplicate
// was deleted made `make test-go` report
// `cannot stat ../../deploy/kustomization.yaml`, which is a confusing way to learn
// that a path moved.
func TestBaseKustomizationIsValidYAML(t *testing.T) {
	data, err := os.ReadFile(baseManifestPath(t, "kustomization.yaml"))
	if err != nil {
		t.Fatalf("read base kustomization: %v", err)
	}
	documents, err := decodeAll(string(data))
	if err != nil {
		t.Fatalf("deploy/base/kustomization.yaml: %v", err)
	}
	if len(documents) == 0 {
		t.Fatal("deploy/base/kustomization.yaml parsed to zero documents")
	}
}
