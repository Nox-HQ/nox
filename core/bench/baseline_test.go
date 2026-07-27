package bench

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestCompareBaseline(t *testing.T) {
	t.Parallel()

	base := Baseline{Precision: 0.30, Recall: 0.80, F1: 0.44, FP: 18, TP: 9, FN: 2, FindingsPerIssue: 3.0}

	tests := []struct {
		name    string
		current Baseline
		want    []string // regressed metric names, in order
	}{
		{
			name:    "identical is no regression",
			current: base,
			want:    nil,
		},
		{
			name:    "precision drop regresses",
			current: Baseline{Precision: 0.25, Recall: 0.80, F1: 0.44, FP: 18, FindingsPerIssue: 3.0},
			want:    []string{"precision"},
		},
		{
			name:    "more false positives regresses",
			current: Baseline{Precision: 0.30, Recall: 0.80, F1: 0.44, FP: 22, FindingsPerIssue: 3.0},
			want:    []string{"fp"},
		},
		{
			name:    "higher findings-per-issue regresses",
			current: Baseline{Precision: 0.30, Recall: 0.80, F1: 0.44, FP: 18, FindingsPerIssue: 4.5},
			want:    []string{"findings_per_issue"},
		},
		{
			name:    "improvement never regresses",
			current: Baseline{Precision: 0.55, Recall: 0.90, F1: 0.68, FP: 10, FindingsPerIssue: 1.5},
			want:    nil,
		},
		{
			name:    "multiple regressions all reported",
			current: Baseline{Precision: 0.20, Recall: 0.70, F1: 0.31, FP: 25, FindingsPerIssue: 5.0},
			want:    []string{"precision", "recall", "f1", "fp", "findings_per_issue"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CompareBaseline(base, tt.current)
			names := make([]string, len(got))
			for i := range got {
				names[i] = got[i].Metric
			}
			if len(names) != len(tt.want) {
				t.Fatalf("regressions = %v, want %v", names, tt.want)
			}
			for i := range tt.want {
				if names[i] != tt.want[i] {
					t.Errorf("regression[%d] = %s, want %s", i, names[i], tt.want[i])
				}
			}
		})
	}
}

// TestCompareBaselinePerRule proves the per-rule ratchet catches a single rule
// regressing even when the overall numbers are untouched — the exact blind spot
// an overall-only floor has. It also proves the schema is backward compatible: a
// baseline with no `rules` section skips per-rule enforcement.
// TestImprovedUnderFiringDensity is the mirror of the gate: for a suite already
// below the 1.00 ideal, sliding FURTHER below means it started missing even more
// findings, so it must not be advertised as an improvement worth snapshotting.
func TestImprovedUnderFiringDensity(t *testing.T) {
	t.Parallel()

	base := Baseline{Precision: 1.0, Recall: 0.857, F1: 0.923, FP: 0, TP: 12, FN: 2, FindingsPerIssue: 0.857}

	// Density alone falls further below the ideal, with every other metric flat.
	worse := Baseline{Precision: 1.0, Recall: 0.857, F1: 0.923, FP: 0, TP: 12, FN: 2, FindingsPerIssue: 0.6}
	if Improved(base, worse) {
		t.Error("a density drop further below the 1.00 ideal must not count as an improvement")
	}

	// Climbing toward the ideal is the real improvement.
	better := Baseline{Precision: 1.0, Recall: 0.857, F1: 0.923, FP: 0, TP: 12, FN: 2, FindingsPerIssue: 0.95}
	if !Improved(base, better) {
		t.Error("a density rise toward the 1.00 ideal must count as an improvement")
	}
}

// TestCompareBaselineUnderFiringDensity pins the direction of the
// findings-per-issue gate. The metric's ideal is 1.00: below it the scanner is
// MISSING findings, above it the scanner is duplicating them. A suite carrying
// honest false negatives sits below 1.0, so closing one of those FNs necessarily
// raises the number — toward the ideal. Gating it as strictly lower-is-better
// reported every such recall win as a regression, which would have forced each
// genuine improvement to be laundered through a baseline regeneration. Only
// movement past the 1.00 ideal (real over-firing) is a regression.
func TestCompareBaselineUnderFiringDensity(t *testing.T) {
	t.Parallel()

	// An under-firing suite: 12 findings across 14 annotated issues.
	base := Baseline{Precision: 1.0, Recall: 0.857, F1: 0.923, FP: 0, TP: 12, FN: 2, FindingsPerIssue: 0.857}

	tests := []struct {
		name    string
		current Baseline
		want    []string
	}{
		{
			name:    "closing a false negative raises density toward 1.0 and is not a regression",
			current: Baseline{Precision: 1.0, Recall: 0.929, F1: 0.963, FP: 0, TP: 13, FN: 1, FindingsPerIssue: 0.929},
			want:    nil,
		},
		{
			name:    "reaching the 1.00 ideal is not a regression",
			current: Baseline{Precision: 1.0, Recall: 1.0, F1: 1.0, FP: 0, TP: 14, FN: 0, FindingsPerIssue: 1.0},
			want:    nil,
		},
		{
			name:    "over-firing past the ideal is a regression",
			current: Baseline{Precision: 1.0, Recall: 1.0, F1: 1.0, FP: 0, TP: 14, FN: 0, FindingsPerIssue: 1.6},
			want:    []string{"findings_per_issue"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CompareBaseline(base, tt.current)
			names := make([]string, len(got))
			for i := range got {
				names[i] = got[i].Metric
			}
			if len(names) != len(tt.want) {
				t.Fatalf("regressions = %v, want %v", names, tt.want)
			}
			for i := range tt.want {
				if names[i] != tt.want[i] {
					t.Errorf("regression[%d] = %s, want %s", i, names[i], tt.want[i])
				}
			}
		})
	}
}

func TestCompareBaselinePerRule(t *testing.T) {
	t.Parallel()

	// Overall metrics are identical in every case; only the per-rule floors and
	// current per-rule numbers differ, isolating the per-rule logic.
	overall := Baseline{Precision: 0.90, Recall: 0.90, F1: 0.90, FP: 2, FindingsPerIssue: 1.0}
	withRules := func(rules ...RuleBaseline) Baseline {
		b := overall
		b.Rules = rules
		return b
	}

	tests := []struct {
		name        string
		base        Baseline
		current     Baseline
		wantMetrics []string
	}{
		{
			name:        "flat per-rule floors are no regression",
			base:        withRules(RuleBaseline{"SEC-001", 1.0, 1.0}, RuleBaseline{"AI-002", 0.5, 1.0}),
			current:     withRules(RuleBaseline{"SEC-001", 1.0, 1.0}, RuleBaseline{"AI-002", 0.5, 1.0}),
			wantMetrics: nil,
		},
		{
			name:        "one rule's precision drop regresses even when overall holds",
			base:        withRules(RuleBaseline{"SEC-001", 1.0, 1.0}, RuleBaseline{"AI-002", 1.0, 1.0}),
			current:     withRules(RuleBaseline{"SEC-001", 0.5, 1.0}, RuleBaseline{"AI-002", 1.0, 1.0}),
			wantMetrics: []string{"SEC-001 precision"},
		},
		{
			name:        "one rule's recall drop regresses",
			base:        withRules(RuleBaseline{"SEC-001", 1.0, 1.0}),
			current:     withRules(RuleBaseline{"SEC-001", 1.0, 0.5}),
			wantMetrics: []string{"SEC-001 recall"},
		},
		{
			name:        "per-rule improvement never regresses",
			base:        withRules(RuleBaseline{"SEC-001", 0.5, 0.5}),
			current:     withRules(RuleBaseline{"SEC-001", 1.0, 1.0}),
			wantMetrics: nil,
		},
		{
			name:        "a floored rule that stopped firing is not a regression (vacuous 1.0)",
			base:        withRules(RuleBaseline{"SEC-001", 1.0, 1.0}),
			current:     overall, // no rules at all in the current run
			wantMetrics: nil,
		},
		{
			name:        "backward compatible: base without rules skips per-rule enforcement",
			base:        overall, // pre-schema snapshot, no rules section
			current:     withRules(RuleBaseline{"SEC-001", 0.0, 0.0}),
			wantMetrics: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CompareBaseline(tt.base, tt.current)
			names := make([]string, len(got))
			for i := range got {
				names[i] = got[i].Metric
			}
			if len(names) != len(tt.wantMetrics) {
				t.Fatalf("regressions = %v, want %v", names, tt.wantMetrics)
			}
			for i := range tt.wantMetrics {
				if names[i] != tt.wantMetrics[i] {
					t.Errorf("regression[%d] = %s, want %s", i, names[i], tt.wantMetrics[i])
				}
			}
		})
	}
}

// TestBaselineFromReportPerRule proves BaselineFromReport records a floor for
// every exercised rule and omits rules the corpus never touched (which would
// otherwise floor at a vacuous 1.0 and gate on unmeasured precision).
func TestBaselineFromReportPerRule(t *testing.T) {
	t.Parallel()

	report := Score(
		[]findings.Finding{
			finding("SEC-001", "a.py", 1), // TP
			finding("AI-002", "b.py", 2),  // FP (no expectation)
		},
		[]Expectation{
			expect("SEC-001", "a.py", 1),
			expect("SEC-510", "c.py", 3), // FN: never fired
		},
	)
	b := BaselineFromReport(&report)

	// All three rules were exercised (SEC-001 TP, AI-002 FP, SEC-510 FN), so all
	// three get a floor. None is unexercised, so none is dropped.
	got := map[string]RuleBaseline{}
	for _, r := range b.Rules {
		got[r.RuleID] = r
	}
	if len(got) != 3 {
		t.Fatalf("recorded %d rule floors %v, want 3", len(got), b.Rules)
	}
	// Rules must be sorted by ID for a stable committed snapshot.
	for i := 1; i < len(b.Rules); i++ {
		if b.Rules[i-1].RuleID > b.Rules[i].RuleID {
			t.Errorf("rule floors not sorted: %s before %s", b.Rules[i-1].RuleID, b.Rules[i].RuleID)
		}
	}
	if p := got["AI-002"].Precision; p != 0.0 {
		t.Errorf("AI-002 (pure FP) precision floor = %v, want 0.0", p)
	}
	if r := got["SEC-510"].Recall; r != 0.0 {
		t.Errorf("SEC-510 (pure FN) recall floor = %v, want 0.0", r)
	}
}

func TestImproved(t *testing.T) {
	t.Parallel()

	base := Baseline{Precision: 0.30, Recall: 0.80, F1: 0.44, FP: 18, FindingsPerIssue: 3.0}

	tests := []struct {
		name    string
		current Baseline
		want    bool
	}{
		{"identical is not an improvement", base, false},
		{"higher precision is an improvement", Baseline{Precision: 0.40, Recall: 0.80, F1: 0.53, FP: 18, FindingsPerIssue: 3.0}, true},
		{"fewer FPs is an improvement", Baseline{Precision: 0.30, Recall: 0.80, F1: 0.44, FP: 10, FindingsPerIssue: 3.0}, true},
		{"lower density is an improvement", Baseline{Precision: 0.30, Recall: 0.80, F1: 0.44, FP: 18, FindingsPerIssue: 1.5}, true},
		{"a regression is not an improvement", Baseline{Precision: 0.20, Recall: 0.80, F1: 0.44, FP: 18, FindingsPerIssue: 3.0}, false},
		// Density is distance-from-1.00, so overshooting the ideal is not a win:
		// 3.0 -> 0.2 swaps heavy duplication for heavy under-firing (distance
		// 2.0 -> 0.8 is closer, so this one IS an improvement), but a suite that
		// starts under 1.00 and falls further is strictly worse. Covered below.
		{"overshooting from over-firing to closer-but-under is an improvement", Baseline{Precision: 0.30, Recall: 0.80, F1: 0.44, FP: 18, FindingsPerIssue: 0.9}, true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Improved(base, tt.current); got != tt.want {
				t.Errorf("Improved = %v, want %v", got, tt.want)
			}
		})
	}
}
