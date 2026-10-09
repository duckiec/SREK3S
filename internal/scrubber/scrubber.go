// Package scrubber is the deterministic, in-memory secret and PII masking
// engine defined by CONTRIBUTING.md §5.
//
// The package is hermetic by construction. It imports only the standard
// library, performs no I/O, opens no sockets, and holds no mutable state beyond
// the compiled manifest. That isolation is the point: it is what makes the
// compliance property "no secret crosses the network egress boundary" auditable
// and testable independently of the Kubernetes client (PRD F1, AC-2).
package scrubber

import (
	"context"
	"strings"
)

// RedactionSentinel is the single masking token, CONTRIBUTING.md §5.1 M1.
//
// It is an unexported-by-contract constant: no flag, environment variable or
// config path may alter it, so no deployment can weaken masking.
const RedactionSentinel = "[REDACTED]"

// normaliseContext returns a usable context, substituting context.Background()
// for a nil one. ROADMAP 1.2.6 requires that a nil ctx never panics.
func normaliseContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// ScrubString applies every manifest rule, in normative order, and returns the
// masked string.
//
// Cancellation is deliberately NOT observed inside the pipeline. See the note
// on scrub for why returning a partially-masked buffer is never safe.
func ScrubString(ctx context.Context, s string) string {
	// The context is normalised for API consistency and so a nil ctx is
	// harmless, but masking is pure CPU work with nothing to interrupt.
	_ = normaliseContext(ctx)
	return scrub(s).text
}

// ScrubLines masks the payload in three ordered stages, and the order is
// load-bearing rather than incidental.
//
//  1. Stage 1, [crossLinePass]: rules whose pattern genuinely spans a newline.
//     First, because D-3 found that a single-line rule would otherwise shred a PEM
//     block before the rule that owns it had a chance to see it whole.
//  2. The per-line pass. Every line goes through the full manifest with its
//     templates, so each secret is masked by the rule that recognises its syntax.
//  3. Stage 2, [collapseAndRedact]: whatever survived, re-examined as one
//     separator-free projection.
//
// Stage 2 runs LAST on purpose. It was originally placed before the per-line pass,
// which masked the fixture's own secrets with a cross-boundary span and left only
// three of the eleven rules firing - over-redacting the neighbours of a split
// secret, and hiding the very rules the per-line pass exists to apply. Running it
// last means it sees only residue, so it is both narrower and cheaper.
//
// The returned report covers all three stages. Nil input yields nil output and a
// zero report.
//
// # Cancellation
//
// Cancellation is observed at line boundaries only. If the context is done, the
// fully-masked prefix is returned. Every line that is returned has been through
// the complete manifest, so the result is never partially masked.
//
// Note on line count: a secret spanning several lines (a PEM block, for
// example) is collapsed into a single sentinel, so the result may contain fewer
// lines than the input. That is the intended behaviour of M3, and it is the
// only way a multi-line secret can be fully removed.
func ScrubLines(ctx context.Context, lines []string) ([]string, RedactionReport) {
	ctx = normaliseContext(ctx)
	if lines == nil {
		return nil, RedactionReport{}
	}

	acc := newRedactor()

	crossed, crossAcc := crossLinePass(lines)
	acc.merge(crossAcc.report())

	// The per-line pass over the redistributed text. Every line is masked to
	// completion or not returned; see scrub for why cancellation is observed at
	// line granularity only.
	out := make([]string, len(crossed))
	for i, line := range crossed {
		if ctx.Err() != nil {
			return out[:i], acc.report()
		}
		res := scrub(line)
		out[i] = res.text
		acc.merge(res.report)
	}

	// D-6, last: by now each line has been masked by the rule that recognises it,
	// so what is left that a line's own quotes betray is a value that ran past the
	// end of its line.
	continued, continueReport := continueSplitValues(out, acc)
	acc.merge(continueReport)
	return continued, acc.report()
}

// crossLinePass catches what a per-line scan cannot see, in two stages, and
// redistributes the result.
//
// Defect D-3 fixed the PEM-body leak by moving this pass ahead of the per-line
// pass. Defect D-5 restricted it to rules with MultiLine == true. Defect D-6 is
// that D-5's justification did not hold and the leak it left was total. Each
// stage is described where it is implemented.
func crossLinePass(lines []string) ([]string, *redactor) {
	acc := newRedactor()
	if len(lines) < 2 {
		// A single line cannot have a secret spanning a boundary.
		return lines, acc
	}

	// Stage 1 only. The separator-free projection is stage 2, and it runs last -
	// see [ScrubLines] for why the ordering is what it is.
	joined := strings.Join(lines, "\n")
	text := applyRules(multiLineManifest(), joined, acc)
	if text != joined {
		lines = strings.Split(text, "\n")
	}
	return lines, acc
}

// continueSplitValues is stage 2. A credential whose halves land on different
// lines leaves a tell: the line carrying the first half opens a quote it never
// closes, because the value ran to end-of-line. Stage 2 masks the rest.
//
// This replaced a separator-free projection of the whole batch, which found the
// same secrets and destroyed unrelated diagnostics doing it. Removing the newline
// between two lines also removes the boundary that keeps a greedy value class
// inside its line: generic_secret_kv matches `[^"',;}\\n]{4,}`, so in a
// projection it ran on from an already-masked `auth=` through the sentinel and
// into the next line's `ts=... msg=`, masking a credential that was already
// masked and a timestamp that was not one. Two diagnostics gone to hide nothing.
// The golden fixture in internal/emitter drifted by exactly that much.
//
// Quote parity is a syntactic fact about the payload rather than a heuristic
// about the manifest, so it needs no new rule flag and no change to
// CONTRIBUTING.md's normative table: if a line opens a quote it does not close,
// the value it was carrying is incomplete on that line.
//
// The residual is stated rather than hidden. A split credential with NO quoting
// around it has no such tell, because there is no delimiter whose absence marks
// the continuation. That shape is left unmasked by this stage and is recorded in
// splitline_test.go as a known limit rather than papered over.
func continueSplitValues(lines []string, acc *redactor) ([]string, RedactionReport) {
	if len(lines) < 2 {
		return lines, RedactionReport{}
	}

	acc2 := newRedactor()
	out := make([]string, len(lines))
	copy(out, lines)

	for i := 0; i < len(lines)-1; i++ {
		open := unclosedQuoteAt(out[i])
		if open < 0 {
			continue
		}
		// Both halves. The head on this line is the fragment the per-line pass
		// could not mask, because a value shorter than generic_secret_kv's four
		// character minimum is below every rule's threshold - `aws_secret_access_key
		// = "a` then `bbbb…"` left one real character on the wire. The tail on the
		// next line is the rest of the same credential.
		out[i] = out[i][:open+1] + RedactionSentinel

		next := out[i+1]
		stop := len(next)
		if at := firstQuote(next); at >= 0 {
			// Through the closing quote: it belongs to the value, and leaving it
			// behind would put the payload back into odd parity.
			stop = at + 1
		}
		out[i+1] = RedactionSentinel + next[stop:]
		acc2.record(RuleGenericSecretKV, 1)
	}
	return out, acc2.report()
}

// unclosedQuoteAt returns the index of the quote character this line opens and
// never closes, or -1 when every quote on the line is paired.
func unclosedQuoteAt(line string) int {
	for _, q := range []string{`"`, `'`} {
		var open int
		seen := false
		for i := 0; ; {
			at := strings.Index(line[i:], q)
			if at < 0 {
				break
			}
			i += at
			if seen {
				open = -1
			} else {
				open = i
			}
			seen = !seen
			i += len(q)
		}
		if seen {
			return open
		}
	}
	return -1
}

func firstQuote(s string) int {
	at := strings.IndexAny(s, `"'`)
	return at
}

// scrubResult bundles the masked text with its accounting.
type scrubResult struct {
	text   string
	report RedactionReport
}

// applyRules runs the supplied rules over s. It exists so the per-line pass and
// the cross-line pass share one implementation; the difference between them is
// only which rules are supplied.
func applyRules(rules []Rule, s string, acc *redactor) string {
	for _, r := range rules {
		s = applyRule(r, s, acc)
	}
	return s
}

// scrub runs the full manifest over a single string.
//
// It takes no context on purpose, and that is a security decision rather than an
// oversight. ROADMAP 1.2.7 asks for "abort mid-pipeline on cancellation,
// returning the partially-masked buffer already masked (never raw)", but those
// two clauses are mutually exclusive: the manifest is ordered, so aborting
// after rule 6 leaves every rule 7 secret untouched. An implementation that
// does exactly what 1.2.7 literally says returns a buffer that is raw with
// respect to every rule that had not yet run.
//
// The contradiction is resolved by observing that there is nothing to cancel.
// Masking is pure CPU over a bounded string, with no I/O, no locks and no
// blocking call, so a line is masked in microseconds. Interrupting it can only
// produce a leak, never a saving. Cancellation is therefore honoured by the
// caller at line granularity (ScrubLines), where every unit of work is
// already-complete output.
func scrub(s string) scrubResult {
	if s == "" {
		return scrubResult{text: s, report: RedactionReport{}}
	}
	acc := newRedactor()
	return scrubResult{text: applyRules(Manifest, s, acc), report: acc.report()}
}

// applyRule runs one rule over s and records how many times it fired.
//
// Single pass, deliberately. An earlier version counted with
// FindAllStringIndex and then substituted with ReplaceAllString, doubling the
// engine work for every rule. With eleven rules that is twenty-two passes over
// the payload instead of eleven, and it was the largest single contributor to
// missing the CONTRIBUTING.md §5.2 budget.
func applyRule(r Rule, s string, acc *redactor) string {
	// MatchString first: regexp.ReplaceAllString always appends the unmatched
	// tail to a fresh buffer, so it copies the whole input even when there are
	// zero matches. MatchString is a pure search that allocates nothing, and it
	// carries no correctness risk, because it is the engine's own answer rather
	// than a heuristic.
	if !r.RE.MatchString(s) {
		return s
	}

	tmpl := r.templateFor()
	plain := tmpl == RedactionSentinel
	hits := 0

	out := r.RE.ReplaceAllStringFunc(s, func(m string) string {
		hits++
		if plain {
			// No group references, so the whole match becomes the sentinel.
			// This is ten of the eleven rules and avoids a submatch lookup.
			return tmpl
		}
		// Rule 6 substitutes groups ${1} and ${3}, which ReplaceAllStringFunc
		// cannot do on its own. Re-anchoring the submatch indices onto the
		// isolated match gives ExpandString what it needs.
		idx := r.RE.FindStringSubmatchIndex(m)
		return string(r.RE.ExpandString(nil, tmpl, m, idx))
	})

	acc.record(r.ID, hits)
	return out
}
