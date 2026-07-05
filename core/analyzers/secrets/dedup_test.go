package secrets

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// mkFinding builds a same-line finding spanning [startCol,endCol) for the given
// rule. Line is fixed unless overridden.
func mkFinding(ruleID string, line, startCol, endCol int) findings.Finding {
	return findings.Finding{
		RuleID:     ruleID,
		Severity:   findings.SeverityHigh,
		Confidence: findings.ConfidenceHigh,
		Location:   findings.Location{StartLine: line, EndLine: line, StartColumn: startCol, EndColumn: endCol},
		Message:    ruleID,
	}
}

// TestDedupBySpecificity asserts that overlapping same-line findings collapse to
// the single most-specific rule, while distinct spans/lines are preserved.
func TestDedupBySpecificity(t *testing.T) {
	// Structural spec ranking mirroring the real analyzer: all providers share
	// one tier, loose secret_shape rules below them, entropy at the bottom.
	spec := map[string]int{
		"SEC-003": specProviderDefault, // GitHub ghp_ prefix
		"SEC-023": specProviderDefault, // Slack xoxb prefix
		"SEC-455": specKeywordGeneric,  // loose 32-char secret_shape rule
		"SEC-161": specGenericEntropy,
		"SEC-162": specGenericEntropy,
		"SEC-163": specGenericEntropy,
	}

	tests := []struct {
		name string
		in   []findings.Finding
		want []string // surviving rule IDs, order-independent
	}{
		{
			name: "provider wins over entropy pileup on same span",
			in: []findings.Finding{
				mkFinding("SEC-003", 2, 17, 57),
				mkFinding("SEC-161", 2, 17, 57),
				mkFinding("SEC-163", 2, 17, 57),
				mkFinding("SEC-163", 2, 21, 57),
			},
			want: []string{"SEC-003"},
		},
		{
			name: "provider wins over loose secret_shape rule",
			in: []findings.Finding{
				mkFinding("SEC-023", 3, 16, 70),
				mkFinding("SEC-455", 3, 16, 70),
				mkFinding("SEC-161", 3, 16, 70),
			},
			want: []string{"SEC-023"},
		},
		{
			name: "two real secrets on different lines both survive",
			in: []findings.Finding{
				mkFinding("SEC-003", 2, 17, 57),
				mkFinding("SEC-161", 2, 17, 57),
				mkFinding("SEC-023", 3, 16, 70),
				mkFinding("SEC-161", 3, 16, 70),
			},
			want: []string{"SEC-003", "SEC-023"},
		},
		{
			name: "non-overlapping spans on same line both kept",
			in: []findings.Finding{
				mkFinding("SEC-003", 5, 10, 20),
				mkFinding("SEC-023", 5, 40, 60),
			},
			want: []string{"SEC-003", "SEC-023"},
		},
		{
			name: "single finding untouched",
			in:   []findings.Finding{mkFinding("SEC-161", 1, 1, 10)},
			want: []string{"SEC-161"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedupBySpecificity(tt.in, spec, nil)
			gotIDs := make(map[string]int)
			for i := range got {
				gotIDs[got[i].RuleID]++
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d findings %v, want %d %v", len(got), ruleIDsOf(got), len(tt.want), tt.want)
			}
			for _, w := range tt.want {
				if gotIDs[w] == 0 {
					t.Errorf("expected surviving rule %s, got %v", w, ruleIDsOf(got))
				}
			}
		})
	}
}

// TestDedupOwnerResolution asserts that when several provider rules match the
// SAME token, only the canonical owner(s) survive — and that AWS's co-canonical
// SEC-001/SEC-508 pair is preserved (both are annotated ground truth).
func TestDedupOwnerResolution(t *testing.T) {
	spec := map[string]int{
		"SEC-001": specProviderDefault, "SEC-508": specProviderDefault,
		"SEC-003": specProviderDefault, "SEC-216": specProviderDefault,
		"SEC-435": specProviderDefault, "SEC-496": specProviderDefault,
		"SEC-030": specProviderDefault, "SEC-103": specProviderDefault,
		"SEC-438": specProviderDefault, "SEC-338": specProviderDefault,
		"SEC-161": specGenericEntropy, "SEC-163": specGenericEntropy,
	}

	t.Run("github token keeps only SEC-003", func(t *testing.T) {
		content := []byte(`GITHUB_TOKEN = "ghp_016C7f8e9d0A1b2C3d4E5f6G7h8I9j0K1l2M"` + "\n")
		// All these matched the ghp_ token span (cols within the value).
		in := []findings.Finding{
			mkFinding("SEC-003", 1, 17, 57),
			mkFinding("SEC-216", 1, 17, 57),
			mkFinding("SEC-435", 1, 17, 22),
			mkFinding("SEC-496", 1, 17, 57),
			mkFinding("SEC-161", 1, 17, 57),
		}
		got := ruleIDsOf(dedupBySpecificity(in, spec, content))
		if len(got) != 1 || got[0] != "SEC-003" {
			t.Fatalf("github: got %v, want [SEC-003]", got)
		}
	})

	t.Run("aws token keeps co-canonical SEC-001 and SEC-508", func(t *testing.T) {
		content := []byte(`AWS_KEY = "AKIAIOSFODNN7EXAMPLE"` + "\n")
		in := []findings.Finding{
			mkFinding("SEC-001", 1, 12, 32),
			mkFinding("SEC-508", 1, 12, 32),
			mkFinding("SEC-161", 1, 12, 32),
		}
		got := ruleIDsOf(dedupBySpecificity(in, spec, content))
		ids := map[string]bool{}
		for _, g := range got {
			ids[g] = true
		}
		if len(got) != 2 || !ids["SEC-001"] || !ids["SEC-508"] {
			t.Fatalf("aws: got %v, want [SEC-001 SEC-508]", got)
		}
	})

	t.Run("stripe token keeps only SEC-030, drops Clerk alias", func(t *testing.T) {
		content := []byte(`STRIPE = "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH1234"` + "\n")
		in := []findings.Finding{
			mkFinding("SEC-030", 1, 11, 54),
			mkFinding("SEC-103", 1, 11, 54), // Clerk sk_ alias
			mkFinding("SEC-438", 1, 11, 19), // Stripe alias
			mkFinding("SEC-338", 1, 11, 55),
			mkFinding("SEC-163", 1, 11, 54),
		}
		got := ruleIDsOf(dedupBySpecificity(in, spec, content))
		if len(got) != 1 || got[0] != "SEC-030" {
			t.Fatalf("stripe: got %v, want [SEC-030]", got)
		}
	})
}

func ruleIDsOf(fs []findings.Finding) []string {
	out := make([]string, len(fs))
	for i := range fs {
		out[i] = fs[i].RuleID
	}
	return out
}

// TestClassifyRuleSpecificity checks the structural ranking derived from the
// real built-in rule set: anchored provider rules outrank loose vendor rules,
// which outrank entropy rules.
func TestClassifyRuleSpecificity(t *testing.T) {
	spec := specificityByRule(NewAnalyzer().engine.Rules().Rules())
	cases := []struct {
		ruleID string
		want   int
	}{
		{"SEC-161", specGenericEntropy}, // entropy floor
		{"SEC-163", specGenericEntropy},
		{"SEC-003", specProviderDefault}, // GitHub provider regex
		{"SEC-023", specProviderDefault}, // Slack provider regex
		{"SEC-007", specProviderDefault}, // GCP provider regex
	}
	for _, c := range cases {
		got, ok := spec[c.ruleID]
		if !ok {
			t.Fatalf("rule %s missing from spec map", c.ruleID)
		}
		if got != c.want {
			t.Errorf("spec[%s] = %d, want %d", c.ruleID, got, c.want)
		}
	}
	// Entropy rules must rank strictly below provider rules.
	if spec["SEC-161"] >= spec["SEC-003"] {
		t.Errorf("entropy SEC-161 (%d) should rank below provider SEC-003 (%d)", spec["SEC-161"], spec["SEC-003"])
	}
}
