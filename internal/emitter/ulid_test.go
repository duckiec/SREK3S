package emitter

import (
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The agent's own pattern, transcribed. If agent/models.py moves, the parity test
// in emitter_test.go fails; these tests are about the encoder, not the pattern.
var agentIncidentIDPattern = regexp.MustCompile(`^inc_[0-9A-HJKMNP-TV-Z]{20,32}$`)

// TestULIDIsDeterministic is the property the retry path depends on.
//
// A random ULID is the conventional choice and would be wrong here: Emit retries
// on 429, and a retry that mints a new ID presents one container failure to the
// agent as two incidents, which the agent would triage twice.
func TestULIDIsDeterministic(t *testing.T) {
	const key = "7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b/checkout-api:4"
	at := time.Date(2026, 9, 28, 14, 32, 7, 481_000_000, time.UTC)

	first, err := newIncidentULID(key, at)
	if err != nil {
		t.Fatalf("newIncidentULID: %v", err)
	}
	second, err := newIncidentULID(key, at)
	if err != nil {
		t.Fatalf("newIncidentULID: %v", err)
	}
	if first != second {
		t.Errorf("not deterministic: %q then %q", first, second)
	}

	other, err := newIncidentULID(key+":5", at)
	if err != nil {
		t.Fatalf("newIncidentULID: %v", err)
	}
	if other == first {
		t.Error("a different dedup key produced the same ULID")
	}
}

// TestULIDMatchesTheAgentPattern is the local half of the round trip.
//
// The cross-language test in agent/tests/test_emitter_contract.py proves the
// whole payload. This proves the encoder, so a failure points at the ULID code
// rather than at the fixture.
func TestULIDMatchesTheAgentPattern(t *testing.T) {
	cases := []struct {
		name string
		key  string
		at   time.Time
	}{
		{"canonical", "7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b/checkout-api:4",
			time.Date(2026, 9, 28, 14, 32, 7, 481_000_000, time.UTC)},
		// A timestamp near the ULID epoch is the interesting case: it produces the
		// most zero bytes, and is where a missing left-pad would emit a short ID.
		{"near-epoch", "a", time.UnixMilli(0).UTC()},
		{"exactly-epoch", "b", time.Unix(0, 0).UTC()},
		{"empty-key", "", time.Now()},
		{"max-bits", "c", time.UnixMilli(1<<48 - 1).UTC()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, err := newIncidentULID(c.key, c.at)
			if err != nil {
				t.Fatalf("newIncidentULID: %v", err)
			}
			if !agentIncidentIDPattern.MatchString(id) {
				t.Errorf("id = %q, does not match the agent's pattern", id)
			}
			// 26 symbols is the canonical ULID width. Anything from 20 to 32
			// satisfies the agent, so this is stricter than it needs to be - and
			// deliberately so, because a variable-width ID is the signature of a
			// padding bug and the agent would accept it silently.
			if len(id) != len(incidentIDPrefix)+ulidLength {
				t.Errorf("id = %q, want %d symbols", id, len(incidentIDPrefix)+ulidLength)
			}
			for _, symbol := range []byte(id[len(incidentIDPrefix):]) {
				if !containsSymbol(crockfordAlphabet, symbol) {
					t.Errorf("symbol %q is outside the Crockford alphabet", symbol)
				}
			}
		})
	}
}

func containsSymbol(alphabet string, symbol byte) bool {
	for i := range len(alphabet) {
		if alphabet[i] == symbol {
			return true
		}
	}
	return false
}

// TestULIDSortsByTime pins the ordering property a ULID is chosen for.
//
// The 48-bit timestamp occupies the most significant bits, so two IDs minted
// microseconds apart must compare in the same order as their timestamps. An
// implementation that put the digest first - or encoded little-endian - would
// produce a well-formed but unordered ID, and nothing else in this package would
// notice.
func TestULIDSortsByTime(t *testing.T) {
	const key = "ordering-probe"
	earlier, err := newIncidentULID(key, time.UnixMilli(1_700_000_000_000))
	if err != nil {
		t.Fatalf("newIncidentULID: %v", err)
	}
	later, err := newIncidentULID(key, time.UnixMilli(1_700_000_000_001))
	if err != nil {
		t.Fatalf("newIncidentULID: %v", err)
	}
	if !(earlier < later) {
		t.Errorf("IDs are not time-ordered: %q then %q", earlier, later)
	}
}

// TestBase32KnownVectors checks the encoder against values worked out by hand.
//
// A base32 encoder has no other oracle: a self-consistent implementation that
// maps the alphabet wrongly passes every round-trip test in this file. These
// vectors pin the two properties that matter - the alphabet maps symbol i to
// value i, and a single high byte produces the symbol you would expect.
func TestBase32KnownVectors(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		// Zero has an encoding, and it is one symbol. The divmod loop exits
		// immediately on an all-zero input, so this is the case that would silently
		// become an empty string without the special case in the encoder.
		{[]byte{0x00}, "0"},
		{[]byte{0x01}, "1"},
		// The all-ones 16-byte value is the maximum: symbol 31 is 'Z', the last
		// character of the Crockford alphabet. 128 bits of 1s is 26 symbols whose
		// leading symbol carries only 3 significant bits, so it is '7'.
		{
			[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			"7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
		},
		// All-zero 16 bytes: still one symbol, and the caller pads it to 26. This is
		// the padding case, and it is why the padding lives in the caller.
		{
			make([]byte, 16),
			"0",
		},
		// 0x80 alone: the most significant bit set in a single byte. Guards the
		// high-bit handling, where a signed byte would go negative and turn the
		// divmod loop inside out. 0x80 is 128, and 128 / 32 = 4 with remainder 0,
		// so it is "40" - the trailing zero is the significant part here.
		{[]byte{0x80}, "40"},
		// 0x20 is exactly 32: one divmod step, quotient 1, remainder 0.
		{[]byte{0x20}, "10"},
		// 0x1f is 31, the last symbol, with an empty quotient.
		{[]byte{0x1f}, "Z"},
		// Two bytes where the second is entirely consumed: 0x0100 is 256, and
		// 256 = 8*32, so quotient [0x08] then 8 = 0*32 + 8.
		{[]byte{0x01, 0x00}, "80"},
	}
	for _, c := range cases {
		got, err := encodeBase32(c.in)
		if err != nil {
			t.Errorf("encodeBase32(%x): %v", c.in, err)
			continue
		}
		// encodeBase32 emits minimally - the width is the caller's choice - so these
		// vectors are exact. The 26-symbol padding is asserted in the ULID tests.
		if got != c.want {
			t.Errorf("encodeBase32(%x) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestBase32RejectsAnEmptyBody is the negative control for the known vectors.
//
// Without it, an encoder that returned "" for everything would fail the vector
// test but a *caller* that skipped validation would emit a bare "inc_" and get a
// 422. Cheap to check, and it proves the error path is reachable.
func TestBase32RejectsAnEmptyBody(t *testing.T) {
	if _, err := encodeBase32(nil); err == nil {
		t.Error("encodeBase32(nil) succeeded; an empty body would emit a bare inc_ prefix")
	}
}

// TestBase32RoundTrips proves the divmod loop is not losing or duplicating bits.
//
// Inputs are all 16 bytes, which is not an arbitrary restriction and is the
// whole reason the width lives in the caller. Minimal base32 encodes a *numeric
// value*, not a byte sequence: 0x0102030405 is the number 16909060, which needs 25
// significant bits and so 5 symbols, not the 8 that 40 bits would suggest. A
// minimal encoding cannot record how many leading zero bytes it dropped, so
// decoding it yields 3 bytes rather than 5. That is a property of the format, not
// a defect here, and asserting an exact byte round trip on a narrow input would be
// asserting something base32 does not promise.
//
// 16 bytes is where the round trip is well defined: 128 bits occupy 26 symbols
// (130 bits, 2 of them implicitly zero because the leading symbol can only hold
// three significant bits), so padding to the known width restores exactly the
// value that went in. That is the shape every real ULID has.
//
// Decoding is an independent inverse - the alphabet is indexed directly rather
// than reusing the encoder - so a systematic error in one direction is not
// mirrored in the other.
func TestBase32RoundTrips(t *testing.T) {
	inputs := [][]byte{
		make([]byte, 16),
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		{0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
			0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00},
		{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
			0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80},
		// A real ULID body: 48-bit timestamp, 80-bit digest.
		{0x01, 0x76, 0x5c, 0x0d, 0xf0, 0x0e,
			0x9f, 0x2c, 0x41, 0x77, 0x8b, 0x03, 0x6e, 0xd1, 0x54, 0xa0},
	}
	for _, in := range inputs {
		encoded, err := encodeBase32(in)
		if err != nil {
			t.Fatalf("encodeBase32(%x): %v", in, err)
		}
		// Pad to the width the caller applies, which is what makes the round trip
		// total. Same expression newIncidentULID uses.
		padded := strings.Repeat(string(crockfordAlphabet[0]), ulidLength-len(encoded)) + encoded
		if len(padded) != ulidLength {
			t.Fatalf("padded width = %d, want %d", len(padded), ulidLength)
		}
		if got := decodeBase32(t, padded, len(in)); !equalBytes(got, in) {
			t.Errorf("round trip of %x gave %x (via %q)", in, got, padded)
		}
	}
}

// decodeBase32 is the inverse of [encodeBase32], written independently so a bug
// in one is not mirrored in the other.
//
// Decoding is done as an integer and then truncated to whole bytes, which is the
// only way to get this right at widths that are not a multiple of 8. 26 symbols is
// 130 bits for a 128-bit value, so the leading symbol carries two padding bits
// that no bit-at-a-time accumulator can distinguish from data - it would emit them
// as the top bits of a 17th byte. Reading the value and taking its low bytes
// discards them by construction.
func decodeBase32(t *testing.T, encoded string, byteCount int) []byte {
	t.Helper()
	value := new(big.Int)
	symbolValue := new(big.Int)
	for i := 0; i < len(encoded); i++ {
		index := strings.IndexByte(crockfordAlphabet, encoded[i])
		if index < 0 {
			t.Fatalf("symbol %q is not in the alphabet", encoded[i])
		}
		// value = value * 32 + index
		value.Lsh(value, 5)
		symbolValue.SetInt64(int64(index))
		value.Add(value, symbolValue)
	}
	// The byte count is a parameter rather than derived from the symbol count,
	// because a minimal encoding does not record how many leading zero bytes were
	// dropped. 26 symbols is 130 bits for a 128-bit value, so the two padding bits
	// are dropped here by construction rather than emitted as a 17th byte.
	return value.FillBytes(make([]byte, byteCount))
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestULIDTimestampIsClampedToItsFieldWidth is the defensive path.
//
// A time outside the 48-bit ULID epoch would otherwise shift digest bits into the
// timestamp field, producing an ID that is valid-looking but does not encode the
// detection time. Only reachable with a badly wrong clock, which is exactly when a
// plausible-looking ID is worst.
func TestULIDTimestampIsClampedToItsFieldWidth(t *testing.T) {
	// 1<<50 exceeds the 48-bit field, and the mask keeps the low 48 bits, so this
	// collides with the timestamp that has exactly those low bits. That collision
	// is the point: it is what proves the high bits were discarded rather than
	// shifted into the digest.
	far := time.UnixMilli(1 << 50).UTC()
	id, err := newIncidentULID("overflow", far)
	if err != nil {
		t.Fatalf("newIncidentULID: %v", err)
	}
	if !agentIncidentIDPattern.MatchString(id) {
		t.Errorf("id = %q is not a valid ULID for an out-of-range timestamp", id)
	}
	equivalent, err := newIncidentULID("overflow", time.UnixMilli(0).UTC())
	if err != nil {
		t.Fatalf("newIncidentULID: %v", err)
	}
	if id != equivalent {
		t.Errorf("an out-of-range timestamp produced %q, want the masked-to-zero "+
			"value %q; the overflow is reaching the digest", id, equivalent)
	}

	// A timestamp inside the field is not affected, which is the negative control:
	// without it, an implementation that masked unconditionally would look correct.
	inRange, err := newIncidentULID("overflow", time.UnixMilli(1_700_000_000_000).UTC())
	if err != nil {
		t.Fatalf("newIncidentULID: %v", err)
	}
	if inRange == equivalent {
		t.Error("an in-range timestamp collapsed onto the zero timestamp")
	}
}
