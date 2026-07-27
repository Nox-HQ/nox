package bench

import (
	"fmt"
	"sort"
)

// A baseline turns the honest precision number into a ratchet. Measuring
// precision once is worth little if it can silently rot; a committed snapshot
// plus a comparison that fails on regression means the number can only move in
// one direction without a human deciding otherwise. This file holds the pure
// comparison — reading and writing the snapshot file is I/O and lives in the CLI.

// Baseline is the committed snapshot of a corpus's headline metrics. It stores
// only the numbers a regression gate compares, not the full per-rule table, so
// the snapshot stays small and stable across cosmetic report changes. A drop in
// precision/recall/F1 or a rise in false positives beyond tolerance is a
// regression; improvements are allowed (and prompt a snapshot refresh).
type Baseline struct {
	// Precision, Recall, F1 are the corpus-wide (Overall) metrics.
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	// FP is the corpus-wide false-positive count. It is gated on directly
	// (not just via precision) because FP is the number the over-firing work is
	// trying to drive down — a rise in raw FP is a regression even if precision
	// happens to hold.
	FP int `json:"fp"`
	// TP and FN are recorded for context in the snapshot and diff output; they
	// are not gated on independently (a rise in TP is good, and FN is already
	// reflected in recall).
	TP int `json:"tp"`
	FN int `json:"fn"`
	// FindingsPerIssue is the headline over-firing metric. A rise here is a
	// regression: it means the scanner started inflating real issues into more
	// duplicate findings even if precision/recall held.
	FindingsPerIssue float64 `json:"findings_per_issue"`
	// Rules is the per-rule precision/recall floor. An overall-only ratchet lets
	// one rule silently regress while another improves and hides it in the
	// average; recording a floor per rule makes each rule defend its own number.
	// It is omitempty and nil-tolerant: a baseline.json written before this field
	// existed simply has no `rules` section, loads fine, and skips per-rule
	// enforcement (backward compatible). Sorted by RuleID for a stable snapshot.
	Rules []RuleBaseline `json:"rules,omitempty"`
}

// RuleBaseline is the floor for a single rule: its precision and recall may not
// drop below these recorded values. Only rules that actually fired or had
// expectations at snapshot time are recorded — a rule the corpus never exercises
// has no meaningful floor and would only add noise to the ratchet.
type RuleBaseline struct {
	RuleID    string  `json:"rule_id"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
}

// BaselineFromReport extracts the gated metrics from a full Report, including
// the per-rule floors. Only rules that were exercised (TP+FP+FN > 0) get a
// floor: an untouched rule scores a vacuous 1.0/1.0 (see RuleMetrics.Precision)
// and recording that would gate on precision the corpus never actually measured.
func BaselineFromReport(r *Report) Baseline {
	b := Baseline{
		Precision:        r.Overall.Precision(),
		Recall:           r.Overall.Recall(),
		F1:               r.Overall.F1(),
		FP:               r.Overall.FP,
		TP:               r.Overall.TP,
		FN:               r.Overall.FN,
		FindingsPerIssue: r.Density.FindingsPerIssue(),
	}
	for i := range r.Rules {
		m := &r.Rules[i]
		if m.TP+m.FP+m.FN == 0 {
			continue
		}
		b.Rules = append(b.Rules, RuleBaseline{
			RuleID:    m.RuleID,
			Precision: m.Precision(),
			Recall:    m.Recall(),
		})
	}
	sort.Slice(b.Rules, func(i, j int) bool { return b.Rules[i].RuleID < b.Rules[j].RuleID })
	return b
}

// BaselineTolerance is the slack the gate allows before calling a metric change
// a regression. Scoring is deterministic so exact equality would work, but a
// small epsilon absorbs floating-point representation noise in the JSON round
// trip and lets a truly-flat run pass. FP is an integer count and uses a small
// absolute tolerance so a single flaky extra finding does not fail CI while a
// real regression (several new FPs) still does.
const (
	baselineEpsilon = 1e-6
	// fpTolerance is how many extra false positives the gate forgives. Kept at 0
	// by default intent (the ratchet should be tight), exposed as a constant so
	// the reason is documented in one place.
	fpTolerance = 0
)

// Regression is a single metric that moved the wrong way past tolerance.
type Regression struct {
	Metric   string
	Baseline float64
	Current  float64
}

// String renders a regression as a human-readable diff line.
func (r Regression) String() string {
	return fmt.Sprintf("%s: %.4f -> %.4f (regressed)", r.Metric, r.Baseline, r.Current)
}

// CompareBaseline reports every metric in current that regressed relative to
// base beyond tolerance. An empty slice means no regression (the run is at or
// better than the baseline). It is pure and does no I/O.
//
// Regression direction: precision/recall/F1 must not DROP; FP and
// findings-per-issue must not RISE. Improvements never register as regressions,
// so a run that legitimately improves passes the gate (and the caller can then
// refresh the snapshot).
func CompareBaseline(base, current Baseline) []Regression {
	var out []Regression
	// Higher-is-better metrics: flag a drop past epsilon.
	if current.Precision < base.Precision-baselineEpsilon {
		out = append(out, Regression{"precision", base.Precision, current.Precision})
	}
	if current.Recall < base.Recall-baselineEpsilon {
		out = append(out, Regression{"recall", base.Recall, current.Recall})
	}
	if current.F1 < base.F1-baselineEpsilon {
		out = append(out, Regression{"f1", base.F1, current.F1})
	}
	// Lower-is-better metrics: flag a rise past tolerance.
	if current.FP > base.FP+fpTolerance {
		out = append(out, Regression{"fp", float64(base.FP), float64(current.FP)})
	}
	// findings-per-issue is a distance-from-ideal metric, not a lower-is-better
	// one: 1.00 means every annotated issue produced exactly one finding. Below
	// 1.00 the scanner is MISSING findings; above it, duplicating them. A suite
	// that carries honest false negatives therefore sits under 1.00, and closing
	// one of those FNs necessarily raises the number toward the ideal. Gating on
	// a bare rise flagged those recall wins as regressions and would have forced
	// every real improvement through a baseline regeneration. Only a rise past
	// the ideal — genuine over-firing — regresses, so the ceiling is
	// max(baseline, 1.0): a suite already over-firing may not get worse, and a
	// suite under-firing may climb to 1.00 freely.
	if ceiling := max(base.FindingsPerIssue, 1.0); current.FindingsPerIssue > ceiling+baselineEpsilon {
		out = append(out, Regression{"findings_per_issue", base.FindingsPerIssue, current.FindingsPerIssue})
	}
	// Per-rule floors: any individual rule whose precision OR recall dropped
	// below its recorded floor is a regression, even when the overall numbers
	// hold (one rule improving can mask another regressing in the average). A
	// base with no per-rule section (a pre-schema snapshot) skips this check
	// entirely, keeping old baselines loadable and gated only on the overall.
	out = append(out, compareRules(base.Rules, current.Rules)...)
	return out
}

// compareRules flags every rule whose current precision or recall fell below its
// baseline floor. Current per-rule numbers are looked up by RuleID; a floored
// rule that no longer appears in current (it stopped firing and had no
// expectation) is treated as a vacuous 1.0/1.0 — its absence is not itself a
// regression, matching how BaselineFromReport declines to floor unexercised
// rules. The Metric name is prefixed with the rule ID so the CLI diff points at
// the exact rule that moved.
func compareRules(base, current []RuleBaseline) []Regression {
	if len(base) == 0 {
		return nil
	}
	byRule := make(map[string]RuleBaseline, len(current))
	for _, r := range current {
		byRule[r.RuleID] = r
	}
	var out []Regression
	for _, b := range base {
		cur, ok := byRule[b.RuleID]
		if !ok {
			// Rule no longer exercised: precision/recall are the vacuous 1.0, so
			// they cannot fall below any floor <= 1.0.
			cur = RuleBaseline{RuleID: b.RuleID, Precision: 1.0, Recall: 1.0}
		}
		if cur.Precision < b.Precision-baselineEpsilon {
			out = append(out, Regression{b.RuleID + " precision", b.Precision, cur.Precision})
		}
		if cur.Recall < b.Recall-baselineEpsilon {
			out = append(out, Regression{b.RuleID + " recall", b.Recall, cur.Recall})
		}
	}
	return out
}

// Improved reports whether current is strictly better than base on any gated
// metric while regressing on none. The CLI uses it to tell the operator a
// snapshot refresh is warranted after a legitimate improvement.
func Improved(base, current Baseline) bool {
	if len(CompareBaseline(base, current)) > 0 {
		return false
	}
	return current.Precision > base.Precision+baselineEpsilon ||
		current.Recall > base.Recall+baselineEpsilon ||
		current.F1 > base.F1+baselineEpsilon ||
		current.FP < base.FP ||
		// Closer to the 1.00 ideal in EITHER direction, mirroring the gate in
		// CompareBaseline. A bare drop is not an improvement: for a suite that
		// already under-fires, falling further below 1.00 means it started
		// missing even more findings.
		densityDistance(current.FindingsPerIssue) < densityDistance(base.FindingsPerIssue)-baselineEpsilon
}

// densityDistance is how far a findings-per-issue value sits from the 1.00
// ideal — one finding per annotated issue. Under 1.00 the scanner misses
// findings, over it duplicates them; the distance makes both directions
// comparable.
func densityDistance(v float64) float64 {
	if v < 1.0 {
		return 1.0 - v
	}
	return v - 1.0
}
