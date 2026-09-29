package scrubber

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

// This file exists to settle one question, raised as an unverified report during
// Milestone 4 fixture authoring: does `${3}` in rule 7's replacement template
// resolve to the *trailing quote* or to the *captured secret*?
//
// The report was derived on .NET, whose submatch numbering for a pattern mixing
// unnamed and named groups was claimed to differ from Go's RE2. If true, that is
// a live credential leak on the component this project exists to prove correct.
//
// Verdict, once measured: **the report is void.** Go numbers a named group exactly
// as if it were unnamed, so the secret is submatch 2 and the trailing quote is
// submatch 3, which is what the template assumes. The .NET expansion that motivated
// the report is a .NET artifact.
//
// The tests stay, because the *claim* was reasonable and the next reader should
// not have to re-derive it. A report that turns out to be wrong is worth pinning
// for the same reason a fix is: the reasoning that reached it was sound and only
// the engine differed, and that is exactly the kind of thing to re-litigate under
// pressure. Every test here fails if the leak is ever real.

// expandAllGroups renders every numbered submatch of a match, so a numbering claim
// is read off the engine rather than inferred from a replacement's output.
//
// Indices are read from the engine rather than by splitting a formatted template.
// The first version of this test built `"${1}||${2}||${3}||${4}"` and indexed the
// split, so `fields[0]` was `${1}` and any group N was read at `fields[N-1]` - the
// reporting was off by one against the very defect it was investigating. A
// mislabelled failure looks identical to a confirmed bug, which is the worst
// possible failure mode for a test whose entire job is to be sure.
func expandAllGroups(t *testing.T, pattern *regexp.Regexp, match []int, subject string) []string {
	t.Helper()
	_ = pattern
	groups := (len(match) - 2) / 2
	out := make([]string, groups+1)
	out[0] = subject[match[0]:match[1]]
	for g := 1; g <= groups; g++ {
		if match[2*g] < 0 {
			out[g] = "" // did not participate in this match
			continue
		}
		out[g] = subject[match[2*g]:match[2*g+1]]
	}
	return out
}

// TestGoSubmatchNumberingForRule7 is the direct answer to the reported leak.
func TestGoSubmatchNumberingForRule7(t *testing.T) {
	rule, ok := ruleByID(RuleGenericSecretKV)
	if !ok {
		t.Fatal("rule 7 is not in the manifest")
	}

	cases := []struct{ subject, secret string }{
		{"password=hunter2", "hunter2"},
		{"password: hunter2", "hunter2"},
		{`{"password":"hunter2"}`, "hunter2"},
		{"api_key = sk-live-abc12345", "sk-live-abc12345"},
		{
			"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}

	for _, c := range cases {
		match := rule.RE.FindStringSubmatchIndex(c.subject)
		if match == nil {
			t.Errorf("rule 7 did not match %q", c.subject)
			continue
		}
		groups := expandAllGroups(t, rule.RE, match, c.subject)

		// The claim under test, as the engine states it.
		if strings.Contains(groups[3], c.secret) {
			t.Errorf("REPRODUCED: for %q submatch 3 is %q and holds the secret.\n"+
				"  groups: %q\n"+
				"  The template ${1}%s${3} would re-emit the credential.",
				c.subject, groups[3], groups, RedactionSentinel)
		}
		if !strings.Contains(groups[2], c.secret) {
			t.Errorf("for %q submatch 2 is %q and does not hold the secret.\n"+
				"  groups: %q\n"+
				"  A named group must be numbered as if it were unnamed.", c.subject, groups[2], groups)
		}
		// Submatch 3's *content* is the direct answer: the trailing quote, or
		// nothing when the value is unquoted. Never the value.
		if got := groups[3]; got != "" && got != `"` && got != "'" {
			t.Errorf("%q: submatch 3 is %q, want the trailing quote (empty, \" or ')",
				c.subject, got)
		}
		// Reachable by name, which is presumably why the author reached for it.
		byName := rule.RE.ExpandString(nil, "${value}", c.subject, match)
		if !strings.Contains(string(byName), c.secret) {
			t.Errorf("%q: ${value} = %q, expected the secret", c.subject, byName)
		}
	}
}

// TestRule7TemplateDoesNotReemitTheSecret is the end-to-end statement: whatever the
// numbering, the *output* must not contain the secret, and must carry the sentinel
// exactly once.
func TestRule7TemplateDoesNotReemitTheSecret(t *testing.T) {
	rule, ok := ruleByID(RuleGenericSecretKV)
	if !ok {
		t.Fatal("rule 7 is not in the manifest")
	}
	subjects := []string{
		"password=hunter2",
		"password: hunter2",
		`{"password":"hunter2"}`,
		"api_key = sk-live-abc12345",
		`{"api_key":"sk-live-abc12345"}`,
		"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	secrets := []string{
		"hunter2", "sk-live-abc12345", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	for _, subject := range subjects {
		got := rule.RE.ReplaceAllString(subject, rule.templateFor())
		for _, secret := range secrets {
			if strings.Contains(got, secret) {
				t.Errorf("input %q produced %q, which still contains %q", subject, got, secret)
			}
		}
		// A count of two is the precise signature of a template that emits the
		// masked value and then the raw one.
		if n := strings.Count(got, RedactionSentinel); n != 1 {
			t.Errorf("input %q produced %q with %d sentinels, want exactly 1", subject, got, n)
		}
	}
}

// TestNoRuleReEmitsACaptureGroup is manifest-wide rather than rule-7-specific.
//
// The reported mechanism - a named group shifting numeric indices - is not
// specific to rule 7, so the durable guard is over the whole manifest. A rule whose
// replacement grows the string beyond input-plus-one-sentinel is re-emitting a
// capture.
func TestNoRuleReEmitsACaptureGroup(t *testing.T) {
	subjects := []string{
		"password=hunter2",
		"api_key=sk-live-abc12345",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
		"dial=postgres://u:Sup3rS3cret@db.internal:5432/x",
		"aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
		`aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
		"trace 7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b done",
	}
	for _, rule := range Manifest {
		for _, subject := range subjects {
			got := rule.RE.ReplaceAllString(subject, rule.templateFor())
			if got == subject {
				continue // rule did not match; nothing to assert
			}
			if len(got) > len(subject)+len(RedactionSentinel) {
				t.Errorf("rule %s turned %q into %q, longer than the input plus one "+
					"sentinel; the template is re-emitting a capture", rule.ID, subject, got)
			}
		}
	}
}

// TestNamedGroupsAreNumberedAsIfUnnamed pins the Go rule the report turned on, so
// the next reader does not have to re-derive it from scratch.
func TestNamedGroupsAreNumberedAsIfUnnamed(t *testing.T) {
	// (a)(?P<value>b)(c) - exactly rule 7's group shape.
	pattern := regexp.MustCompile(`^(a)(?P<value>b)(c)$`)
	match := pattern.FindStringSubmatchIndex("abc")
	if match == nil {
		t.Fatal("the control pattern did not match")
	}
	groups := expandAllGroups(t, pattern, match, "abc")

	for index, want := range map[int]string{0: "abc", 1: "a", 2: "b", 3: "c"} {
		if groups[index] != want {
			t.Errorf("submatch %d = %q, want %q (full: %q)", index, groups[index], want, groups)
		}
	}
	// The specific trap the report fell into: assuming the named group consumed an
	// extra index, so the trailing quote would be ${4} and ${3} would be the value.
	if len(groups) == 5 && groups[4] == "b" {
		t.Error("the named group was assigned its own index; Go does not do that")
	}
}

// TestScrubberOutputForTheReportedCases is the plain-language version: what a user
// actually sees.
func TestScrubberOutputForTheReportedCases(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"password=hunter2", "password=" + RedactionSentinel},
		{`{"password":"hunter2"}`, `{"password":"` + RedactionSentinel + `"}`},
		{"api_key = sk-live-abc12345", "api_key = " + RedactionSentinel},
	} {
		if got := ScrubString(context.Background(), c.in); got != c.want {
			t.Errorf("ScrubString(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
