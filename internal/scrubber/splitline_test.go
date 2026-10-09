package scrubber

import (
	"context"
	"strings"
	"testing"
)

// D-6: a credential split across a line boundary must not reach the payload.
//
// This is the regression for the defect where crossLinePass ran only the one
// rule with MultiLine == true, on the reasoning that the other ten "provably
// cannot match across a newline". They cannot - but the reason was wrong. A rule
// like aws_secret_access_key matches a run of exactly forty characters; joining
// two lines leaves twenty characters, a newline, and twenty more, so the pattern
// fails because the newline sits inside the run it is looking for. Every split
// credential reached the egress boundary in full, and the redaction report said
// total=0.
//
// The test asserts on surviving characters rather than on contiguity: a credential
// split by a newline is still leaked if both halves are in the payload, because a
// consumer joins them with one join.

// leaked reports whether the payload still carries any reassemblable part of a
// credential that was split across a line boundary.
//
// The property is reassembly, not character membership. A consumer joins the
// lines with one join, so the secret is recoverable exactly when its halves are
// both still present verbatim. Counting "does this character appear anywhere"
// would fail in the other direction: the key name legitimately contains the same
// letters as the value, so asserting that a single 'a' is absent from
// `aws_secret_access_key` is asserting the impossible.
//
// head is skipped below 4 characters, which is generic_secret_kv's value minimum:
// a fragment that short is indistinguishable from ordinary prose and the manifest
// does not claim to mask it. The tail is asserted at every cut, because that is
// where the bulk of a real credential sits.
func leaked(head, tail string, out []string) (bool, string) {
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, tail) {
		return true, joined
	}
	if len(head) >= 4 && strings.Contains(joined, head) {
		return true, joined
	}
	return false, joined
}

func TestNoCredentialSurvivesALineBoundary(t *testing.T) {
	t.Parallel()
	secret := strings.Repeat("a", 20) + strings.Repeat("b", 20)

	for cut := 1; cut < len(secret); cut++ {
		lines := []string{
			`aws_secret_access_key = "` + secret[:cut],
			secret[cut:] + `"`,
		}
		out, rep := ScrubLines(context.Background(), lines)
		if bad, joined := leaked(secret[:cut], secret[cut:], out); bad {
			t.Errorf("cut=%2d: a credential half reached the payload (reassemblable): %q report=%+v",
				cut, joined, rep)
		}
		if strings.Contains(strings.Join(out, "\n"), secret) {
			t.Errorf("cut=%2d: the whole credential reached the payload: %q", cut, out)
		}
		if rep.Total == 0 {
			t.Errorf("cut=%2d: the report claims nothing was redacted; a silent miss is how this shipped",
				cut)
		}
	}
}

// The single-line control: this one was never broken, and a fix that regresses it
// would trade a boundary leak for a total one.
func TestTheSingleLineControlStillMasksCompletely(t *testing.T) {
	t.Parallel()
	secret := strings.Repeat("a", 20) + strings.Repeat("b", 20)
	out, rep := ScrubLines(context.Background(), []string{`aws_secret_access_key = "` + secret + `"`})
	t.Logf("out=%q total=%d rules=%v", out, rep.Total, rep.RulesTriggered)
	if strings.Contains(strings.Join(out, "\n"), secret) {
		t.Errorf("single-line secret reached the payload: %q", out)
	}
}

// The PEM control: the rule the cross-line pass was built for, and the one D-3
// reordered the pass to protect.
func TestThePEMControlStillMasksAcrossLines(t *testing.T) {
	t.Parallel()
	block := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"MIIBOgIBAAJBAKabcdefghijklmnop",
		"qrstuvwxyz0123456789ABCDEFGH",
		"-----END RSA PRIVATE KEY-----",
	}
	out, rep := ScrubLines(context.Background(), block)
	t.Logf("out=%q total=%d rules=%v", out, rep.Total, rep.RulesTriggered)
	if strings.Contains(strings.Join(out, "\n"), "MIIBOgIBAAJBAK") {
		t.Errorf("PEM body survived: %q", out)
	}
}

// A rule whose pattern cannot match a run split by a newline must still mask it.
// generic_secret_kv is the one that reported success while leaving 36 characters
// of the value, because its template masked the key half only.
func TestGenericSecretKVDoesNotReportSuccessWhileLeavingTheValue(t *testing.T) {
	t.Parallel()
	secret := "s3cr3tvalue1234567890abcdefghijKLMNOP"
	for cut := 1; cut < len(secret); cut++ {
		lines := []string{
			`password = "` + secret[:cut],
			secret[cut:] + `"`,
		}
		out, rep := ScrubLines(context.Background(), lines)
		if bad, joined := leaked(secret[:cut], secret[cut:], out); bad {
			t.Errorf("cut=%2d: a value half survived under a rule that reported %d redaction(s): %q",
				cut, rep.Total, joined)
		}
	}
}

// Over-redaction is the accepted cost and must not grow without bound: two
// unrelated lines that merely sit near each other are left alone.
func TestUnrelatedNeighbouringLinesAreNotBlanked(t *testing.T) {
	t.Parallel()
	lines := []string{
		"CHAOS-OOM iteration=6 heap_bytes=67108864",
		"CHAOS-PHASE creds-planted next=memory-exhaustion",
		"pod srek3s-chaos-oom restarted 3 times",
		"kubectl get pods -n sentinel-chaos",
	}
	out, rep := ScrubLines(context.Background(), lines)
	for i := range lines {
		if out[i] != lines[i] {
			t.Errorf("line %d was modified with no secret present: %q -> %q", i, lines[i], out[i])
		}
	}
	if rep.Total != 0 {
		t.Errorf("expected a zero report, got %+v", rep)
	}
}

// The projection is separator-free, so a secret split with *nothing* between the
// halves must also be caught: that is the shape a wrapped JSON string produces.
func TestAKeyAndValueOnAdjacentLinesAreBothMasked(t *testing.T) {
	t.Parallel()
	lines := []string{
		`{"api_key": "AKIAIOSFODNN7EXAMPLE"`,
		`"client_secret": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}`,
	}
	out, rep := ScrubLines(context.Background(), lines)
	t.Logf("out=%q report=%+v", out, rep)
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("access key survived: %q", out)
	}
	if strings.Contains(joined, "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY") {
		t.Errorf("client secret survived: %q", out)
	}
}
