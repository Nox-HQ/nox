// Package bench provides a precision/recall scorer for nox's SAST rules.
//
// nox already reports rule fire-rates (how often each rule triggers across a
// corpus), but fire-rate says nothing about *quality*: a rule that fires on
// every file might be all noise. To improve precision you must be able to
// measure it, and to measure it you need ground truth. This package supplies
// that missing measurement layer.
//
// Ground truth comes from a labeled corpus (see corpus.go): every finding a
// scan *should* produce is declared inline in the sample source with a
// `nox-expect: <RuleID>` annotation on the line that should fire. Score then
// compares an actual scan's findings against those expectations and computes,
// per rule and overall, true positives (TP), false positives (FP), false
// negatives (FN), and the derived precision, recall, and F1.
//
// The scorer is deliberately a pure function of (findings, expectations) so it
// is fully unit-testable without running a scan — the scan is I/O, the scoring
// is arithmetic, and keeping them separate is what makes the quality number
// trustworthy and reproducible.
package bench

import (
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// Expectation is a single declared ground-truth finding: rule RuleID is
// expected to fire at FilePath:Line. It is produced by parsing `nox-expect`
// annotations out of the corpus (see ParseCorpus). Line is 1-based to match
// findings.Location.StartLine.
type Expectation struct {
	RuleID   string
	FilePath string
	Line     int
}

// RuleMetrics holds the confusion-matrix counts for one rule (or, when RuleID
// is empty, the overall totals) plus the derived precision/recall/F1.
//
// The counts are the source of truth; Precision/Recall/F1 are computed on
// demand so callers can trust them to always agree with TP/FP/FN.
type RuleMetrics struct {
	RuleID string `json:"rule_id,omitempty"`
	TP     int    `json:"tp"`
	FP     int    `json:"fp"`
	FN     int    `json:"fn"`
	// Precision, Recall, F1 are serialized for JSON consumers so downstream
	// tooling doesn't have to recompute them. They are always recomputed from
	// the counts by Score.
	PrecisionValue float64 `json:"precision"`
	RecallValue    float64 `json:"recall"`
	F1Value        float64 `json:"f1"`
}

// Precision is TP / (TP + FP): of the findings this rule reported, the fraction
// that were real. A rule that reports nothing (TP+FP == 0) has no false
// positives, so precision is defined as the perfect 1.0 — this avoids a rule
// that never fires being scored as "bad" and keeps overall averages sane.
func (m *RuleMetrics) Precision() float64 {
	den := m.TP + m.FP
	if den == 0 {
		return 1.0
	}
	return float64(m.TP) / float64(den)
}

// Recall is TP / (TP + FN): of the findings that should have fired, the
// fraction that did. With no expectations (TP+FN == 0) recall is defined as
// 1.0 — nothing was missed because nothing was owed.
func (m *RuleMetrics) Recall() float64 {
	den := m.TP + m.FN
	if den == 0 {
		return 1.0
	}
	return float64(m.TP) / float64(den)
}

// F1 is the harmonic mean of precision and recall. When both are zero (e.g. a
// rule with only false positives, or only false negatives) F1 is 0.
func (m *RuleMetrics) F1() float64 {
	p, r := m.Precision(), m.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

// Report is the full scoring result: one RuleMetrics per rule that appeared in
// either the findings or the expectations, plus an Overall roll-up. Rules is
// sorted worst-precision-first (ties broken by rule ID) so the CLI can render
// the rules most in need of attention at the top without re-sorting.
//
// Density carries the over-firing view of the same findings (see density.go):
// per-rule precision cannot see that one issue tripped seven rules, so Density
// re-slices by issue location to make that inflation measurable. Families groups
// the per-rule metrics by rule-ID prefix (SEC-, AI-, TAINT-, ...) so the report
// can surface which whole rule family is the worst precision offender.
type Report struct {
	Rules    []RuleMetrics   `json:"rules"`
	Overall  RuleMetrics     `json:"overall"`
	Density  DensityReport   `json:"density"`
	Families []FamilyMetrics `json:"families"`
}

// FamilyMetrics rolls the per-rule confusion counts up to a rule-ID family (the
// prefix before the first '-', e.g. SEC, AI, TAINT). Over-firing tends to
// cluster within a family — one secret trips many SEC- rules — so the family
// view names the culprit group directly and is sorted worst-precision-first.
type FamilyMetrics struct {
	Family string `json:"family"`
	RuleMetrics
}

// expectationKey identifies a distinct ground-truth slot. Two expectations
// with the same rule/file/line are the same slot and can only be satisfied
// once.
type expectationKey struct {
	rule string
	file string
	line int
}

// Score compares actual scan findings against declared expectations and
// returns per-rule and overall precision/recall/F1.
//
// Matching rule: a finding is a true positive when there is an unsatisfied
// expectation for the same RuleID and FilePath whose anchor line falls within
// the finding's [StartLine, EndLine] range. Each expectation can be satisfied
// by at most one finding; a second finding matching an already-satisfied
// expectation is a false positive (so duplicate findings are penalised, which
// is the honest behaviour — duplicates are noise to a human triager). A finding
// with no matching expectation is a false positive. An expectation left
// unsatisfied after all findings are considered is a false negative.
//
// Score is pure: it does no I/O and does not mutate its arguments.
func Score(scanFindings []findings.Finding, expectations []Expectation) Report {
	// Index expectations by key and track which have been satisfied. Using a
	// count lets several identical expectations (unusual, but possible) each be
	// matched once.
	remaining := make(map[expectationKey]int, len(expectations))
	for _, e := range expectations {
		remaining[expectationKey{e.RuleID, e.FilePath, e.Line}]++
	}

	// Per-rule counters. We seed every rule that appears in either input so a
	// rule with only FNs (never fired) still shows up in the report.
	tp := map[string]int{}
	fp := map[string]int{}
	fn := map[string]int{}
	seen := map[string]struct{}{}
	seenRule := func(id string) { seen[id] = struct{}{} }

	// fileFP tracks false positives per file so the density view (density.go)
	// and the per-rule view agree on the FP total by construction rather than
	// recomputing it from a different code path.
	fileFP := map[string]int{}

	for _, e := range expectations {
		seenRule(e.RuleID)
	}

	for i := range scanFindings {
		f := &scanFindings[i]
		seenRule(f.RuleID)

		if key, ok := matchExpectation(f, remaining); ok {
			remaining[key]--
			tp[f.RuleID]++
			continue
		}
		fp[f.RuleID]++
		fileFP[f.Location.FilePath]++
	}

	// Anything still remaining is a false negative.
	for key, count := range remaining {
		if count > 0 {
			fn[key.rule] += count
		}
	}

	report := Report{}
	for rule := range seen {
		m := RuleMetrics{RuleID: rule, TP: tp[rule], FP: fp[rule], FN: fn[rule]}
		fillDerived(&m)
		report.Rules = append(report.Rules, m)
		report.Overall.TP += m.TP
		report.Overall.FP += m.FP
		report.Overall.FN += m.FN
	}
	fillDerived(&report.Overall)

	sortWorstPrecisionFirst(report.Rules)
	report.Families = rollUpFamilies(report.Rules)
	report.Density = scoreDensity(scanFindings, expectations, fileFP)
	return report
}

// rollUpFamilies groups per-rule metrics by family prefix (the text before the
// first '-') and returns the aggregated confusion counts per family, sorted
// worst-precision-first. A rule ID with no '-' is its own family. This exists so
// the report can point at a whole misbehaving family ("SEC- over-fires") rather
// than making a human eyeball twenty individual SEC- rows.
func rollUpFamilies(rules []RuleMetrics) []FamilyMetrics {
	byFamily := map[string]*FamilyMetrics{}
	var order []string
	for i := range rules {
		r := &rules[i]
		fam := familyOf(r.RuleID)
		fm, ok := byFamily[fam]
		if !ok {
			fm = &FamilyMetrics{Family: fam, RuleMetrics: RuleMetrics{RuleID: fam}}
			byFamily[fam] = fm
			order = append(order, fam)
		}
		fm.TP += r.TP
		fm.FP += r.FP
		fm.FN += r.FN
	}

	out := make([]FamilyMetrics, 0, len(order))
	for _, fam := range order {
		fm := byFamily[fam]
		fillDerived(&fm.RuleMetrics)
		out = append(out, *fm)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := &out[i], &out[j]
		pa, pb := a.Precision(), b.Precision()
		if pa != pb {
			return pa < pb
		}
		if a.FP != b.FP {
			return a.FP > b.FP
		}
		return a.Family < b.Family
	})
	return out
}

// familyOf returns the rule-ID family: the substring before the first '-'. IDs
// without a '-' are their own family so nothing is silently bucketed together.
func familyOf(ruleID string) string {
	if i := strings.IndexByte(ruleID, '-'); i > 0 {
		return ruleID[:i]
	}
	return ruleID
}

// matchExpectation finds an unsatisfied expectation that the finding satisfies:
// same rule and file, with the expectation's anchor line inside the finding's
// line range. Returns the matched key so the caller can decrement it. A finding
// whose EndLine is zero (unset) is treated as a single line at StartLine.
func matchExpectation(f *findings.Finding, remaining map[expectationKey]int) (expectationKey, bool) {
	start := f.Location.StartLine
	end := f.Location.EndLine
	if end < start {
		end = start
	}
	for line := start; line <= end; line++ {
		key := expectationKey{f.RuleID, f.Location.FilePath, line}
		if remaining[key] > 0 {
			return key, true
		}
	}
	return expectationKey{}, false
}

// fillDerived recomputes the precision/recall/F1 fields from the counts so the
// serialized values can never drift from TP/FP/FN.
func fillDerived(m *RuleMetrics) {
	m.PrecisionValue = m.Precision()
	m.RecallValue = m.Recall()
	m.F1Value = m.F1()
}

// sortWorstPrecisionFirst orders rules so the least precise rule is first — the
// rules most worth fixing surface at the top of the CLI table. Ties in
// precision are broken by more false positives first (louder = higher
// priority), then by rule ID for determinism.
func sortWorstPrecisionFirst(rules []RuleMetrics) {
	sort.Slice(rules, func(i, j int) bool {
		a, b := &rules[i], &rules[j]
		pa, pb := a.Precision(), b.Precision()
		if pa != pb {
			return pa < pb
		}
		if a.FP != b.FP {
			return a.FP > b.FP
		}
		return a.RuleID < b.RuleID
	})
}
