package scrubber

import "sort"

// RedactionReport is the per-call accounting record required by
// CONTRIBUTING.md §5.1 M4.
//
// It is deliberately counts-only. It records which rules fired and how often,
// never what they matched: no plaintext, no prefix, no suffix, and no reversible
// hash. The report is safe to log, attach to a payload, or ship to the agent,
// which is the point of having one at all.
type RedactionReport struct {
	// Total is the number of redactions performed across all rules.
	Total int
	// RulesTriggered lists the rules that fired, deduplicated, in manifest
	// order so that output is byte-stable across runs.
	RulesTriggered []RuleID
}

// redactor accumulates redactions for one scrub call.
type redactor struct {
	total  int
	counts map[RuleID]int
	seen   map[RuleID]struct{}
	// order records first-seen order. Rules are applied in manifest order, so
	// this is already manifest order; it is kept explicitly so the guarantee
	// does not depend on a subtle property of the pipeline.
	order []RuleID
}

func newRedactor() *redactor {
	return &redactor{
		counts: make(map[RuleID]int, len(manifestOrder)),
		seen:   make(map[RuleID]struct{}, len(manifestOrder)),
	}
}

// record notes that a rule fired count times.
func (r *redactor) record(id RuleID, count int) {
	if count <= 0 {
		return
	}
	r.total += count
	r.counts[id] += count
	r.mark(id)
}

// mark notes a rule as triggered without attributing hits to it. It is
// deliberately separate from record: conflating the two made Total
// double-count, because merging a report added its Total and then added one
// more per triggered rule. A 1-redaction scrub reported 3.
func (r *redactor) mark(id RuleID) {
	if _, ok := r.seen[id]; ok {
		return
	}
	r.seen[id] = struct{}{}
	r.order = append(r.order, id)
}

// merge folds another report into this one, preserving manifest order.
func (r *redactor) merge(other RedactionReport) {
	if other.Total == 0 && len(other.RulesTriggered) == 0 {
		return
	}
	r.total += other.Total
	for _, id := range other.RulesTriggered {
		r.mark(id)
	}
}

// report materialises the accumulated counts.
//
// RulesTriggered is sorted by manifest position rather than alphabetically, so
// that two identical inputs always produce byte-identical reports.
func (r *redactor) report() RedactionReport {
	out := make([]RuleID, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, id)
	}
	if len(out) == 0 {
		// Keep a nil slice rather than an empty one so a clean payload does not
		// marshal as [] where the schema expects null.
		return RedactionReport{Total: 0, RulesTriggered: nil}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return manifestIndex(out[i]) < manifestIndex(out[j])
	})
	return RedactionReport{Total: r.total, RulesTriggered: out}
}

// manifestIndex returns a rule's position in the normative order.
func manifestIndex(id RuleID) int {
	for i, m := range manifestOrder {
		if m == id {
			return i
		}
	}
	return len(manifestOrder) // unknown sorts last
}

// mergeReports combines two reports, deduplicating and ordering by manifest
// position. Used by the cross-line pass, whose findings must fold into the same
// accounting as the per-line pass.
func mergeReports(reports ...RedactionReport) RedactionReport {
	r := newRedactor()
	for _, rep := range reports {
		r.merge(rep)
	}
	return r.report()
}
