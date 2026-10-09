package scrubber

import (
	"context"
	"strings"
	"testing"
)

// A split credential with no quoting has no continuation marker: there is no
// delimiter whose absence signals "the value ran past this line". Stage 2 keys off
// an unclosed quote, so it does not fire here.
//
// This test pins the limit instead of pretending it does not exist, so a later
// reader can tell a deliberate boundary from an unnoticed one. If someone extends
// stage 2 to cover this shape, the log line below should become a failure.
// The head half needs its own test, because the boundary test above cannot carry
// it: it skips head assertions below generic_secret_kv's four-character value
// minimum, since a two-character fragment is indistinguishable from prose. That
// skip leaves the short-head case unasserted, and the stage-2 code that masks it
// is load-bearing precisely there and nowhere else.
//
// For every cut of 4 or more, the per-line pass already masks the head by itself -
// which is why removing the head masking from stage 2 broke nothing until this
// test existed.
func TestAShortHeadFragmentIsStillMasked(t *testing.T) {
	t.Parallel()
	secret := "s3cr3tvalue1234567890abcdefghijKLMNOP"
	for _, cut := range []int{1, 2, 3} {
		lines := []string{
			`password = "` + secret[:cut],
			secret[cut:] + `"`,
		}
		out, rep := ScrubLines(context.Background(), lines)
		joined := strings.Join(out, "\n")
		// Assert on the value position rather than on substring absence: a
		// one-character fragment cannot be asserted absent, because `password`
		// itself contains that character.
		open := strings.Index(out[0], `= "`) + 3
		if open <= 2 {
			t.Fatalf("cut=%d: fixture no longer has the shape this asserts on: %q", cut, out[0])
		}
		if value := out[0][open:]; value != RedactionSentinel && value != RedactionSentinel+`"` {
			t.Errorf("cut=%d: the value position holds %q, not a sentinel, so the %d-character "+
				"head fragment survived below every rule's minimum: %q report=%+v",
				cut, value, cut, out, rep)
		}
		if strings.Contains(joined, secret[cut:]) {
			t.Errorf("cut=%d: the tail fragment survived: %q", cut, out)
		}
	}
}

func TestTheUnquotedSplitIsAKnownLimit(t *testing.T) {
	t.Parallel()
	secret := "s3cr3tvalue1234567890abcdefghijKLMNOP"
	lines := []string{
		"authorization: " + secret[:10],
		secret[10:],
	}
	out, rep := ScrubLines(context.Background(), lines)
	joined := strings.Join(out, "\n")
	t.Logf("unquoted split: out=%q report=%+v", out, rep)

	if strings.Contains(joined, secret[10:]) {
		t.Logf("KNOWN LIMIT, still open: the unquoted continuation survives, because stage 2 " +
			"fires only on an unclosed quote. The first fragment is masked by the per-line pass, " +
			"so this is a partial leak rather than the total one the original defect produced.")
		return
	}
	t.Log("the unquoted split is now covered; tighten continueSplitValues to the quoted case")
}
