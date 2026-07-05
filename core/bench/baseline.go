package bench

import "fmt"

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
}

// BaselineFromReport extracts the gated metrics from a full Report.
func BaselineFromReport(r *Report) Baseline {
	return Baseline{
		Precision:        r.Overall.Precision(),
		Recall:           r.Overall.Recall(),
		F1:               r.Overall.F1(),
		FP:               r.Overall.FP,
		TP:               r.Overall.TP,
		FN:               r.Overall.FN,
		FindingsPerIssue: r.Density.FindingsPerIssue(),
	}
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
	if current.FindingsPerIssue > base.FindingsPerIssue+baselineEpsilon {
		out = append(out, Regression{"findings_per_issue", base.FindingsPerIssue, current.FindingsPerIssue})
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
		current.FindingsPerIssue < base.FindingsPerIssue-baselineEpsilon
}
