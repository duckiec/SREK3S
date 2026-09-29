package deploy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// decodeAll parses a multi-document YAML stream into `map[string]any` values.
//
// Typed as `any` rather than typed structs on purpose. A struct would validate the
// manifest against a schema this file defines, and a manifest could then satisfy
// every assertion here while being un-admittable by the apiserver - a Deployment
// with a misspelled field parses cleanly into a struct with the field absent. The
// generic form sees exactly what the YAML says, including typos, which is what a
// manifest test needs to see.
func decodeAll(text string) ([]map[string]any, error) {
	decoder := yaml.NewDecoder(strings.NewReader(text))
	var documents []map[string]any
	for {
		var document map[string]any
		err := decoder.Decode(&document)
		if err == io.EOF {
			return documents, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}
		if document != nil {
			documents = append(documents, document)
		}
	}
}

// byKind returns the documents of one kind.
func byKind(documents []map[string]any, kind string) []map[string]any {
	var found []map[string]any
	for _, document := range documents {
		if document["kind"] == kind {
			found = append(found, document)
		}
	}
	return found
}

// one returns exactly one document of a kind.
func one(documents []map[string]any, kind string) (map[string]any, error) {
	found := byKind(documents, kind)
	if len(found) != 1 {
		return nil, fmt.Errorf("expected exactly one %s, found %d", kind, len(found))
	}
	return found[0], nil
}

// dig walks a path through nested maps.
//
// Tolerates a non-map at any level by returning nil rather than panicking, which
// is what a Go map access does naturally - `m["missing"]` on a `map[string]any` is
// legal and yields the zero value. The type switch is only needed because a YAML
// scalar is `any` rather than a map.
func dig(root any, path ...string) any {
	current := root
	for _, key := range path {
		asMap, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = asMap[key]
	}
	return current
}

// digSlice walks to a key and asserts it is a sequence.
func digSlice(root any, path ...string) ([]any, bool) {
	value := dig(root, path...)
	slice, ok := value.([]any)
	return slice, ok
}

// strList converts a YAML sequence to strings.
func strList(t interface{ Fatalf(string, ...any) }, value any, what string) []string {
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("%s is %T, want a sequence", what, value)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("%s contains a %T, want a string", what, item)
		}
		out = append(out, text)
	}
	return out
}

// readRepoFile reads a repository file relative to this package, so the tests do
// not depend on the working directory.
func readRepoFile(t *testing.T, path ...string) string {
	t.Helper()
	parts := append([]string{"..", ".."}, path...)
	full := filepath.Join(parts...)
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("read %s: %v", full, err)
	}
	return string(data)
}

// parseIntAfter reads the integer literal following a marker in source text.
//
// A crude scan, and deliberately so: the alternative is importing a Go parser to
// read one constant, and a test that cross-references a value between two files
// does not need full syntactic fidelity. It does need to fail loudly when the
// marker moves, which is why a missing marker is a Fatalf rather than a zero.
func parseIntAfter(t *testing.T, source string, marker string) int {
	t.Helper()
	index := strings.Index(source, marker)
	if index < 0 {
		t.Fatalf("marker %q not found; update this test", marker)
	}
	rest := source[index+len(marker):]
	end := strings.IndexFunc(rest, func(r rune) bool {
		return r < '0' || r > '9'
	})
	if end < 0 {
		t.Fatalf("no integer follows %q", marker)
	}
	value, err := strconv.Atoi(rest[:end])
	if err != nil {
		t.Fatalf("integer after %q: %v", marker, err)
	}
	return value
}
