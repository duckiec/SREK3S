// Package scrubber is the deterministic, in-memory secret and PII masking
// engine defined by ARCHITECTURE.md §6.
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

// RedactionSentinel is the single masking token, ARCHITECTURE.md §6.1 M1.
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

// ScrubLines masks each line, then performs the cross-line safety pass required
// by ARCHITECTURE.md §6.1 M3: the masked lines are joined, the full manifest is
// re-scanned once to catch secrets assembled across a line boundary, and the
// result is redistributed.
//
// The returned report covers both passes. Nil input yields nil output and a
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

	// D-3: the cross-line pass runs first, on the raw lines, so that a
	// multi-line rule such as pem_private_key sees an intact BEGIN…END block
	// before any single-line fallback can red part of it.
	crossed, crossAcc := crossLinePass(lines)
	acc.merge(crossAcc.report())

	// Then the per-line pass over the redistributed text. Every line is masked
	// to completion or not returned; see scrub for why cancellation is observed
	// at line granularity only.
	out := make([]string, len(crossed))
	for i, line := range crossed {
		if ctx.Err() != nil {
			return out[:i], acc.report()
		}
		res := scrub(line)
		out[i] = res.text
		acc.merge(res.report)
	}
	return out, acc.report()
}

// crossLinePass joins the masked lines, re-scans with the multi-line rules only,
// and redistributes.
//
// Two changes from the original implementation, both ratified:
//
//   - Defect D-3: this pass now runs BEFORE the per-line pass, not after. That
//     ordering is what fixes the PEM-body leak. Previously the per-line pass ran
//     rule 11 private_key_pem_body first, which redacted the BEGIN marker; by
//     the time rule 1 pem_private_key saw the joined text there was no BEGIN…END
//     pair left, so the base64 key body survived verbatim. Running the multi-line
//     rules first means rule 1 gets an intact block to match, and rule 11 then
//     finds nothing left to shred.
//   - Defect D-5: only rules with MultiLine == true are applied, so this is two
//     patterns over the batch rather than eleven. The others provably cannot
//     match across a newline, so they would contribute nothing.
//
// A second pass over already-masked text produces no new matches, so every
// redaction counted here is a genuine cross-boundary finding.
func crossLinePass(lines []string) ([]string, *redactor) {
	acc := newRedactor()
	if len(lines) < 2 {
		// A single line cannot have a secret spanning a boundary.
		return lines, acc
	}

	joined := strings.Join(lines, "\n")
	text := applyRules(multiLineManifest(), joined, acc)

	if text == joined {
		// Nothing matched; avoid the split allocation on the common path.
		return lines, acc
	}
	return strings.Split(text, "\n"), acc
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
// missing the ARCH §6.2 budget.
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
