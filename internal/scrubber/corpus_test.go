package scrubber

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusFixture is the on-disk shape of tests/fixtures/incident_corpus.json.
//
// The file is data, not code, so adding coverage means editing JSON rather than
// writing a new test. That is the point: the corpus is the acceptance artifact
// for AC-2, and it should be reviewable by someone who does not read Go.
type corpusFixture struct {
	Version string        `json:"version"`
	Groups  []corpusGroup `json:"groups"`
}

type corpusGroup struct {
	Name      string       `json:"name"`
	Rule      string       `json:"rule"`
	Note      string       `json:"note"`
	Multiline bool         `json:"multiline"`
	Cases     []corpusCase `json:"cases"`
}

type corpusCase struct {
	ID           string   `json:"id"`
	Line         string   `json:"line"`
	Lines        []string `json:"lines"`
	Secret       string   `json:"secret"`
	ExpectMasked bool     `json:"expect_masked"`
	MustSurvive  []string `json:"must_survive"`
}

// corpusFile is the fixture filename.
const corpusFile = "incident_corpus.json"

// loadCorpus locates and parses tests/fixtures/incident_corpus.json.
//
// The path is resolved by walking up from the working directory rather than by
// assuming a fixed relative depth. A compiled test binary can be executed from
// any directory, so "../../tests/..." is not reliable: the same binary failed
// when run from the package directory and succeeded when run from the repo
// root. Walking up until the file is found makes the lookup independent of
// where the test happens to run.
func loadCorpus(t testing.TB) corpusFixture {
	t.Helper()

	path, err := findCorpus()
	if err != nil {
		t.Fatalf("locate corpus: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus %s: %v", path, err)
	}
	var f corpusFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse corpus %s: %v", path, err)
	}
	if len(f.Groups) == 0 {
		t.Fatalf("corpus %s contains no groups", path)
	}
	return f
}

// findCorpus walks up from the working directory looking for the fixture.
func findCorpus() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		candidate := filepath.Join(dir, "tests", "fixtures", corpusFile)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%s not found in any parent of the working directory", corpusFile)
		}
		dir = parent
	}
}

// totalCases counts the cases across all groups, for the coverage log.
func (f corpusFixture) totalCases() int {
	n := 0
	for _, g := range f.Groups {
		n += len(g.Cases)
	}
	return n
}

// TestCorpusFixtureIsValid guards the fixture itself, so a typo in the JSON
// fails as a fixture error rather than as a confusing masking failure.
func TestCorpusFixtureIsValid(t *testing.T) {
	t.Parallel()

	f := loadCorpus(t)
	if f.Version == "" {
		t.Error("corpus has no version")
	}

	ids := map[string]bool{}
	maskedCount, cleanCount := 0, 0

	for _, g := range f.Groups {
		if g.Name == "" {
			t.Errorf("a group has no name")
		}
		for _, c := range g.Cases {
			switch {
			case c.ID == "":
				t.Errorf("group %q has a case with no id", g.Name)
			case ids[c.ID]:
				t.Errorf("duplicate case id %q", c.ID)
			}
			ids[c.ID] = true

			if c.Line == "" && len(c.Lines) == 0 {
				t.Errorf("case %q has neither line nor lines", c.ID)
			}
			if c.Line != "" && len(c.Lines) > 0 {
				t.Errorf("case %q sets both line and lines", c.ID)
			}
			// A case that claims masking must name the secret, or the leak
			// assertion has nothing to check against.
			if c.ExpectMasked && c.Secret == "" {
				t.Errorf("case %q expects masking but names no secret", c.ID)
			}
			if c.ExpectMasked {
				maskedCount++
			} else {
				cleanCount++
			}
		}
	}

	t.Logf("corpus %s: %d groups, %d cases (%d expect masking, %d negative controls)",
		f.Version, len(f.Groups), f.totalCases(), maskedCount, cleanCount)

	// A corpus made only of positive cases cannot detect over-masking.
	if cleanCount == 0 {
		t.Error("corpus has no negative controls; over-masking would go undetected")
	}
	if maskedCount < 10 {
		t.Errorf("corpus has only %d masking cases; too thin to be meaningful", maskedCount)
	}
}

// TestCorpusTotalMasking is ROADMAP 1.4.2: every case expecting a redaction
// must contain the sentinel afterwards.
func TestCorpusTotalMasking(t *testing.T) {
	t.Parallel()

	f := loadCorpus(t)
	ctx := context.Background()
	total, masked, negatives := 0, 0, 0

	for _, g := range f.Groups {
		for _, c := range g.Cases {
			total++
			var out string
			if g.Multiline && len(c.Lines) > 0 {
				lines, _ := ScrubLines(ctx, c.Lines)
				out = strings.Join(lines, "\n")
			} else {
				out = ScrubString(ctx, c.Line)
			}

			if c.ExpectMasked {
				if !strings.Contains(out, sentinel) {
					t.Errorf("group %q case %q produced no redaction\n  in:  %q\n  out: %q",
						g.Name, c.ID, input(c), out)
					continue
				}
				masked++
			} else {
				// Negative control: must be untouched, sentinel included.
				if strings.Contains(out, sentinel) {
					t.Errorf("OVER-MASK: negative control %q was modified\n  in:  %q\n  out: %q",
						c.ID, input(c), out)
					continue
				}
				if out != input(c) {
					t.Errorf("OVER-MASK: negative control %q was modified\n  in:  %q\n  out: %q",
						c.ID, input(c), out)
					continue
				}
				negatives++
			}
		}
	}

	t.Logf("corpus: %d/%d cases masked (%d negative controls preserved)", masked, total, negatives)
	if masked == 0 {
		t.Fatal("no corpus case was masked; the corpus is not exercising the manifest")
	}
}

// TestNoPlaintextSecretSurvives is ROADMAP 1.4.3 and the AC-2 core assertion:
// for every named plaintext secret, a substring scan of the output returns zero
// matches. Zero tolerance, no sampling.
func TestNoPlaintextSecretSurvives(t *testing.T) {
	t.Parallel()

	f := loadCorpus(t)
	ctx := context.Background()
	checked, leaks := 0, 0

	for _, g := range f.Groups {
		for _, c := range g.Cases {
			if c.Secret == "" {
				continue
			}
			checked++

			var out string
			if g.Multiline && len(c.Lines) > 0 {
				lines, _ := ScrubLines(ctx, c.Lines)
				out = strings.Join(lines, "\n")
			} else {
				out = ScrubString(ctx, c.Line)
			}

			if strings.Contains(out, c.Secret) {
				leaks++
				t.Errorf("SECRET LEAK: case %q leaked %q\n  in:  %q\n  out: %q",
					c.ID, c.Secret, input(c), out)
			}

			// A truncated prefix is still a leak: an 8-character window of an
			// AWS key is often enough to be useful to an attacker, and the
			// prefix is a common way for a partially-applied rule to show up.
			if len(c.Secret) >= 8 {
				if p := c.Secret[:8]; strings.Contains(out, p) {
					leaks++
					t.Errorf("SECRET LEAK: case %q leaked the prefix %q\n  out: %q", c.ID, p, out)
				}
			}
		}
	}

	t.Logf("AC-2: %d corpus secrets scanned, %d leaks", checked, leaks)
	if leaks != 0 {
		t.Errorf("AC-2 FAILED: %d plaintext secrets survived scrubbing", leaks)
	}
}

// TestCorpusPreservesDiagnostics asserts the RCA-critical property from ARCH
// §6.1 M5 and the §6.3 rationale: masking must not remove the evidence an
// engineer reasons over.
func TestCorpusPreservesDiagnostics(t *testing.T) {
	t.Parallel()

	f := loadCorpus(t)
	ctx := context.Background()
	checked := 0

	for _, g := range f.Groups {
		for _, c := range g.Cases {
			if len(c.MustSurvive) == 0 {
				continue
			}
			checked++

			var out string
			if g.Multiline && len(c.Lines) > 0 {
				lines, _ := ScrubLines(ctx, c.Lines)
				out = strings.Join(lines, "\n")
			} else {
				out = ScrubString(ctx, c.Line)
			}

			for _, keep := range c.MustSurvive {
				if !strings.Contains(out, keep) {
					t.Errorf("case %q lost diagnostic text %q\n  in:  %q\n  out: %q",
						c.ID, keep, input(c), out)
				}
			}
		}
	}
	t.Logf("checked %d cases for preserved diagnostics", checked)
}

// TestCorpusIdempotence is ROADMAP 1.4.4 applied to the fixture, so idempotence
// is verified over the same data the AC-2 assertions use.
func TestCorpusIdempotence(t *testing.T) {
	t.Parallel()

	f := loadCorpus(t)
	ctx := context.Background()

	for _, g := range f.Groups {
		for _, c := range g.Cases {
			if g.Multiline && len(c.Lines) > 0 {
				once, _ := ScrubLines(ctx, c.Lines)
				twice, _ := ScrubLines(ctx, once)
				if strings.Join(once, "\n") != strings.Join(twice, "\n") {
					t.Errorf("case %q is not idempotent\n  1st: %q\n  2nd: %q",
						c.ID, strings.Join(once, "\n"), strings.Join(twice, "\n"))
				}
				continue
			}
			once := ScrubString(ctx, c.Line)
			twice := ScrubString(ctx, once)
			if once != twice {
				t.Errorf("case %q is not idempotent\n  in:   %q\n  1st:  %q\n  2nd:  %q",
					c.ID, c.Line, once, twice)
			}
		}
	}
}

// input renders a case for a failure message.
func input(c corpusCase) string {
	if len(c.Lines) > 0 {
		return strings.Join(c.Lines, "\n")
	}
	return c.Line
}

// corpusBenchmarkLines loads the corpus and flattens it into a benchmark slice,
// so the ARCH §6.2 figure is measured against the same data the AC-2
// assertions verify rather than a separate synthetic fixture.
func corpusBenchmarkLines(tb testing.TB) []string {
	tb.Helper()

	f := loadCorpus(tb)
	var out []string
	for _, g := range f.Groups {
		for _, c := range g.Cases {
			if len(c.Lines) > 0 {
				out = append(out, c.Lines...)
				continue
			}
			out = append(out, c.Line)
		}
	}

	// Repeat to a representative batch size, cycling so the mix stays realistic.
	target := benchLineTarget
	for len(out) < target {
		out = append(out, out...)
	}
	return out[:max(target, len(out))]
}
