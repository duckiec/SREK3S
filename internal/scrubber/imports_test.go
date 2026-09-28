package scrubber

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
)

// packageImports parses the package's own **non-test** source files and returns
// the set of imported package paths.
//
// It backs TestNoDiskArtifacts (ROADMAP 1.4.10, ARCH §6.1 M2): the masking
// engine must be in-memory only, so an `os`, `io` or `net/http` import in the
// shipped code is a defect even if that code happens not to write anything
// today.
//
// Test files are excluded deliberately. The corpus fixture must be read from
// disk, so the test suite imports os, and asserting against the whole directory
// would fail for a legitimate reason. The constraint is about what ships, so
// this inspects what ships.
func packageImports() map[string]bool {
	out := map[string]bool{}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", isNonTestFile, parser.ImportsOnly)
	if err != nil {
		// A parse failure is itself a failure of the gate; surface it as a
		// sentinel the test will report.
		out["<parse error>"] = true
		return out
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, spec := range file.Imports {
				if spec.Path == nil {
					continue
				}
				path, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					continue
				}
				out[path] = true
			}
		}
	}
	return out
}

// isNonTestFile filters out _test.go files for the import audit.
func isNonTestFile(info os.FileInfo) bool {
	return !strings.HasSuffix(info.Name(), "_test.go")
}
