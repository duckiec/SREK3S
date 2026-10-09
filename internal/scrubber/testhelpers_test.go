package scrubber

import (
	"os"
	"strings"
	"testing"
)

// readFile and unindentYAMLBlock lift the embedded scrubber.json document out of
// the shipped ConfigMap, so the strict-decode tests run against the file that
// actually ships rather than a transcription that can drift from it.
func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func unindentYAMLBlock(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	indent := -1
	for _, line := range lines {
		if indent < 0 {
			if strings.HasPrefix(strings.TrimSpace(line), "scrubber.json: |") {
				indent = len(line) - len(strings.TrimLeft(line, " "))
			}
			continue
		}
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" {
			continue
		}
		current := len(line) - len(trimmed)
		if current <= indent {
			break
		}
		out = append(out, line[indent+2:])
	}
	if len(out) == 0 {
		panic("scrubber.json block not found; the ConfigMap layout changed")
	}
	return strings.Join(out, "\n")
}
