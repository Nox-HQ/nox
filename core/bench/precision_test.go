package bench

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// finding is a tiny helper that builds a findings.Finding at a given
// rule/file/line so the table cases below stay readable.
func finding(ruleID, file string, line int) findings.Finding {
	return findings.Finding{
		RuleID: ruleID,
		Location: findings.Location{
			FilePath:  file,
			StartLine: line,
			EndLine:   line,
		},
	}
}

// expect builds an Expectation for the table cases.
func expect(ruleID, file string, line int) Expectation {
	return Expectation{RuleID: ruleID, FilePath: file, Line: line}
}

func TestScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		findings     []findings.Finding
		expectations []Expectation
		// wantRule maps ruleID -> expected {TP, FP, FN}. Overall is checked
		// separately from the sum so a bug in aggregation is visible.
		wantRule    map[string][3]int
		wantOverall [3]int
	}{
		{
			name:         "empty corpus, no findings",
			findings:     nil,
			expectations: nil,
			wantRule:     map[string][3]int{},
			wantOverall:  [3]int{0, 0, 0},
		},
		{
			name:         "single true positive",
			findings:     []findings.Finding{finding("SEC-001", "a.py", 3)},
			expectations: []Expectation{expect("SEC-001", "a.py", 3)},
			wantRule:     map[string][3]int{"SEC-001": {1, 0, 0}},
			wantOverall:  [3]int{1, 0, 0},
		},
		{
			name:         "false positive on a clean line (no expectation)",
			findings:     []findings.Finding{finding("SEC-001", "clean.py", 5)},
			expectations: nil,
			wantRule:     map[string][3]int{"SEC-001": {0, 1, 0}},
			wantOverall:  [3]int{0, 1, 0},
		},
		{
			name:         "false negative: expectation with no finding",
			findings:     nil,
			expectations: []Expectation{expect("AI-002", "p.py", 2)},
			wantRule:     map[string][3]int{"AI-002": {0, 0, 1}},
			wantOverall:  [3]int{0, 0, 1},
		},
		{
			name: "same rule fires on wrong line: one FP + one FN, not a TP",
			findings: []findings.Finding{
				finding("SEC-001", "a.py", 9),
			},
			expectations: []Expectation{expect("SEC-001", "a.py", 3)},
			wantRule:     map[string][3]int{"SEC-001": {0, 1, 1}},
			wantOverall:  [3]int{0, 1, 1},
		},
		{
			name: "finding within a multi-line expectation range counts as TP",
			findings: []findings.Finding{
				// Finding spans lines 4-4 but the expectation is declared on
				// line 3 which opens a 3..6 range; a match on any covered line
				// is a TP. We model the expectation as a single anchor line and
				// match findings whose StartLine equals it OR whose range
				// covers it.
				{RuleID: "SEC-510", Location: findings.Location{FilePath: "a.py", StartLine: 3, EndLine: 6}},
			},
			expectations: []Expectation{expect("SEC-510", "a.py", 3)},
			wantRule:     map[string][3]int{"SEC-510": {1, 0, 0}},
			wantOverall:  [3]int{1, 0, 0},
		},
		{
			name: "different rule at the expected line is FP + FN",
			findings: []findings.Finding{
				finding("SEC-081", "a.py", 3),
			},
			expectations: []Expectation{expect("SEC-001", "a.py", 3)},
			wantRule: map[string][3]int{
				"SEC-001": {0, 0, 1},
				"SEC-081": {0, 1, 0},
			},
			wantOverall: [3]int{0, 1, 1},
		},
		{
			name: "two findings of the same rule at the same line satisfy one expectation; the duplicate is a FP",
			findings: []findings.Finding{
				finding("SEC-001", "a.py", 3),
				finding("SEC-001", "a.py", 3),
			},
			expectations: []Expectation{expect("SEC-001", "a.py", 3)},
			wantRule:     map[string][3]int{"SEC-001": {1, 1, 0}},
			wantOverall:  [3]int{1, 1, 0},
		},
		{
			name: "mixed corpus with several rules",
			findings: []findings.Finding{
				finding("SEC-001", "secret.py", 1), // TP
				finding("SEC-508", "secret.py", 1), // FP (no expectation)
				finding("AI-002", "prompt.py", 2),  // TP
				finding("AI-002", "clean.py", 10),  // FP
			},
			expectations: []Expectation{
				expect("SEC-001", "secret.py", 1),
				expect("AI-002", "prompt.py", 2),
				expect("SEC-510", "secret.py", 2), // FN: never found
			},
			wantRule: map[string][3]int{
				"SEC-001": {1, 0, 0},
				"SEC-508": {0, 1, 0},
				"AI-002":  {1, 1, 0},
				"SEC-510": {0, 0, 1},
			},
			wantOverall: [3]int{2, 2, 1},
		},
		{
			name: "file path is compared verbatim: a match on a different file is FP + FN",
			findings: []findings.Finding{
				finding("SEC-001", "other.py", 3),
			},
			expectations: []Expectation{expect("SEC-001", "a.py", 3)},
			wantRule: map[string][3]int{
				"SEC-001": {0, 1, 1},
			},
			wantOverall: [3]int{0, 1, 1},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			report := Score(tt.findings, tt.expectations)

			// Per-rule assertions.
			gotRule := map[string][3]int{}
			for i := range report.Rules {
				r := report.Rules[i]
				gotRule[r.RuleID] = [3]int{r.TP, r.FP, r.FN}
			}
			if len(gotRule) != len(tt.wantRule) {
				t.Fatalf("rule count: got %d rules %v, want %d %v",
					len(gotRule), gotRule, len(tt.wantRule), tt.wantRule)
			}
			for rule, want := range tt.wantRule {
				got, ok := gotRule[rule]
				if !ok {
					t.Errorf("rule %s missing from report", rule)
					continue
				}
				if got != want {
					t.Errorf("rule %s: got TP/FP/FN %v, want %v", rule, got, want)
				}
			}

			// Overall assertions.
			gotOverall := [3]int{report.Overall.TP, report.Overall.FP, report.Overall.FN}
			if gotOverall != tt.wantOverall {
				t.Errorf("overall: got TP/FP/FN %v, want %v", gotOverall, tt.wantOverall)
			}
		})
	}
}

func TestMetricsPrecisionRecallF1(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		tp, fp, fn    int
		wantPrecision float64
		wantRecall    float64
		wantF1        float64
	}{
		{"perfect", 10, 0, 0, 1.0, 1.0, 1.0},
		{"half precision", 5, 5, 0, 0.5, 1.0, 2.0 / 3.0},
		{"half recall", 5, 0, 5, 1.0, 0.5, 2.0 / 3.0},
		{"no findings, no expectations: precision undefined -> 1.0", 0, 0, 0, 1.0, 1.0, 1.0},
		{"only false positives: precision 0, recall undefined -> 1.0", 0, 3, 0, 0.0, 1.0, 0.0},
		{"only false negatives: recall 0, precision undefined -> 1.0", 0, 0, 4, 1.0, 0.0, 0.0},
		{"mixed", 8, 2, 4, 0.8, 8.0 / 12.0, 2 * 0.8 * (8.0 / 12.0) / (0.8 + 8.0/12.0)},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := RuleMetrics{RuleID: "X", TP: tt.tp, FP: tt.fp, FN: tt.fn}
			if got := m.Precision(); !almostEqual(got, tt.wantPrecision) {
				t.Errorf("precision: got %v, want %v", got, tt.wantPrecision)
			}
			if got := m.Recall(); !almostEqual(got, tt.wantRecall) {
				t.Errorf("recall: got %v, want %v", got, tt.wantRecall)
			}
			if got := m.F1(); !almostEqual(got, tt.wantF1) {
				t.Errorf("f1: got %v, want %v", got, tt.wantF1)
			}
		})
	}
}

func almostEqual(a, b float64) bool {
	const eps = 1e-9
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < eps
}
