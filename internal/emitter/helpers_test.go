package emitter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/srek3s/sentinel/internal/scrubber"
)

// Test-only helpers, kept in their own file so emitter_test.go stays about
// behaviour rather than about reflection plumbing.

func isError(err, target error) bool { return errors.Is(err, target) }

// contextTODO is a placeholder for the two tests that need a live context to
// reach a transport. Exists so those call sites read as deliberate rather than as
// an oversight, and so a future change has one place to look.
func contextTODO() context.Context { return context.Background() }

// scrubLines runs the real scrubber over a slice, which is what production does.
func scrubLines(lines []string) ([]string, scrubber.RedactionReport) {
	return scrubber.ScrubLines(context.Background(), lines)
}

// httptestServer starts a server that answers every request with a fixed status.
func httptestServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	rec := &recorder{}
	return httptest.NewServer(rec.handler(status, body))
}

func asEmitError(t *testing.T, err error) *EmitError {
	t.Helper()
	var emitErr *EmitError
	if !errors.As(err, &emitErr) {
		t.Fatalf("err = %v, want an *EmitError so the caller can branch on Outcome", err)
	}
	return emitErr
}

// corpusCase is one entry from the ratified scrubber corpus.
type corpusCase struct {
	id           string
	text         string
	secret       string
	expectMasked bool
}

// corpusFile reads the ratified corpus. The same fixture internal/scrubber's own
// tests use, so the leak assertion is tied to the ratified reference rather than to
// a list of secrets this file decided were interesting.
func corpusFile(t *testing.T) []corpusCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "incident_corpus.json"))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var fixture struct {
		Groups []struct {
			Cases []struct {
				ID           string   `json:"id"`
				Line         string   `json:"line"`
				Lines        []string `json:"lines"`
				Secret       string   `json:"secret"`
				ExpectMasked bool     `json:"expect_masked"`
			} `json:"cases"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	var cases []corpusCase
	for _, group := range fixture.Groups {
		for _, c := range group.Cases {
			text := c.Line
			if text == "" && len(c.Lines) > 0 {
				text = strings.Join(c.Lines, "\n")
			}
			if text == "" {
				continue
			}
			cases = append(cases, corpusCase{
				id: c.ID, text: text, secret: c.Secret, expectMasked: c.ExpectMasked,
			})
		}
	}
	return cases
}

func corpusCases(t *testing.T) []corpusCase { return corpusFile(t) }

// corpusSecrets is corpusFile reduced to the secret strings.
func corpusSecrets(t *testing.T) []string {
	var secrets []string
	for _, c := range corpusFile(t) {
		if c.secret != "" {
			secrets = append(secrets, c.secret)
		}
	}
	return secrets
}

// jsonFieldNames returns the JSON names of a struct's fields.
//
// Reads the `json` tag rather than the Go field name, because the tag is the
// contract: a field called `ScrubbedLogs` serialising as `raw_logs` is exactly the
// defect the structural test looks for, and a name-based check would miss it.
func jsonFieldNames(structType reflect.Type) map[string]bool {
	fields := make(map[string]bool, structType.NumField())
	for i := range structType.NumField() {
		tag, ok := structType.Field(i).Tag.Lookup("json")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		fields[name] = true
	}
	return fields
}
