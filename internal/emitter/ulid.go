package emitter

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Deterministic ULID generation for `incident_id`.
//
// agent/models.py constrains `incident_id` to `^inc_[0-9A-HJKMNP-TV-Z]{20,}$` -
// an "inc_" prefix followed by a Crockford base32 body, the ULID alphabet. An
// earlier version of this file emitted `"inc_<millis>_<hex digest>"`, which is
// lowercase, underscore-separated, and outside the alphabet. It passed every Go
// test and would have failed as a 422 in production - which is the argument for
// having the cross-language round trip at all, and the reason it is in the gate
// rather than in a checklist.
//
// The alphabet is Crockford base32, not RFC 4648: `I`, `L`, `O` and `U` are
// excluded to remove transcription ambiguity, and the character set is
// case-insensitive by specification. The consumer's regex is upper-case only, so
// this emits upper-case.

// crockfordAlphabet is the 32-symbol base32 alphabet, in value order 0-31.
//
// The four omissions are the point of Crockford: I/1, L/1, O/0 and U/V are the
// pairs a human mistypes when reading an ID aloud or off a screen. A wrong symbol
// would decode to a different ID, so they are left unassigned rather than merely
// discouraged.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ulidLength is the standard ULID length: 26 symbols encoding 128 bits.
//
// 26 * 5 = 130 bits, so the leading symbol carries only 3 significant bits and is
// always in 0-3. That is not a defect, it is how a 128-bit value fits a base32
// alphabet without wasting a symbol - and it is why the encoding below emits
// exactly 26 symbols from 16 bytes.
const ulidLength = 26

// ulidTimeBits is the size of a ULID's millisecond timestamp field.
const ulidTimeBits = 48

// newIncidentULID builds a 26-symbol ULID that is deterministic in its given
// inputs.
//
// Deterministic rather than random, and that is a deliberate departure from how
// ULIDs are normally minted. A random ULID would be the obvious choice, and it
// would be wrong here: [Client.Emit] retries on 429, and a retry that draws a
// fresh random ID presents the same container failure to the agent as a brand new
// incident. The agent would triage it twice and could emit two remediation diffs
// for one failure. Determinism makes the retry idempotent at the identity level,
// which is the property that actually matters for an at-least-once transport.
//
// Uniqueness still holds for the case that matters: two *different* incidents
// hash to different digests, and a repeat of the *same* incident is meant to
// collide. Cryptographic rather than a cheap hash, because a cluster running many
// pods in the same millisecond is not a rare event and a 32-bit hash would
// collide in production long before anyone reproduced it.
func newIncidentULID(entropy string, at time.Time) (string, error) {
	digest := sha256.Sum256([]byte(entropy))

	// Assemble the 128-bit value big-endian: 48 bits of millisecond timestamp
	// followed by 80 bits of digest. High bits first, so the timestamp ordering
	// property of a ULID holds and the IDs sort by detection time.
	var value [16]byte
	timestamp := uint64(at.UnixMilli())
	// The mask is defensive. time.UnixMilli on a time far outside the ULID epoch
	// would otherwise shift the high bits of the digest into the timestamp field
	// and produce an ID that is not the one described above.
	if timestamp >= 1<<ulidTimeBits {
		timestamp &= 1<<ulidTimeBits - 1
	}
	binary.BigEndian.PutUint64(value[0:8], timestamp<<16)
	copy(value[6:], digest[:10])

	// Left-pad to the fixed width. A value whose top bits are zero encodes in
	// fewer symbols - a timestamp near the ULID epoch is the realistic case - and
	// a variable-width ID would still satisfy the agent's `{20,32}` bound while
	// looking like a different shape of thing.
	encoded, err := encodeBase32(value[:])
	if err != nil {
		return "", err
	}
	if len(encoded) > ulidLength {
		return "", fmt.Errorf("emitter: ULID body is %d symbols, want %d", len(encoded), ulidLength)
	}
	return incidentIDPrefix + strings.Repeat(string(crockfordAlphabet[0]), ulidLength-len(encoded)) + encoded, nil
}

// encodeBase32 renders bytes as Crockford base32, big-endian, minimally.
//
// Minimal, with no left padding: the caller decides the width. Padding inside the
// encoder would make the output ambiguous, because a value that legitimately
// begins with zero symbols and a padded value that also begins with zero symbols
// would be indistinguishable - so a round trip could not tell whether the leading
// zeros were data or padding.
//
// Big-endian because a ULID's leading symbols carry the most significant bits:
// little-endian would put the timestamp at the *end* of the string and break the
// sort-by-time property.
func encodeBase32(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("emitter: cannot encode an empty ULID body")
	}

	// Repeated divmod by 32, least-significant symbol first, then reversed. The
	// carry is at most 31 so a byte plus a carry cannot overflow the accumulator.
	remainder := make([]byte, len(data))
	copy(remainder, data)
	symbols := make([]byte, 0, ulidLength)
	for len(remainder) > 0 {
		var quotient []byte
		carry := 0
		for _, b := range remainder {
			accumulator := carry<<8 | int(b)
			quotient = append(quotient, byte(accumulator/32))
			carry = accumulator % 32
		}
		symbols = append(symbols, crockfordAlphabet[carry])
		remainder = trimLeadingZeros(quotient)
	}
	// An all-zero input produces no symbols at all, since the divmod loop exits as
	// soon as the remainder is empty. Zero has an encoding - it is "0" - and a
	// caller that padded to a fixed width would otherwise emit an empty string.
	if len(symbols) == 0 {
		return string(crockfordAlphabet[0]), nil
	}

	// Reverse in place: symbols were collected least-significant first.
	for i, j := 0, len(symbols)-1; i < j; i, j = i+1, j-1 {
		symbols[i], symbols[j] = symbols[j], symbols[i]
	}
	return string(symbols), nil
}

func trimLeadingZeros(data []byte) []byte {
	for i, b := range data {
		if b != 0 {
			return data[i:]
		}
	}
	return nil
}
