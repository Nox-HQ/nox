package bench

import "testing"

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
