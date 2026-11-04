package findings

import "testing"

// With no policy, any active finding fails the scan, except a dependency
// finding nox decided is not impacting: the scan established that the
// vulnerable code is not in, or not reached by, this build (#1012).
func TestGatesByDefault(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		want bool
	}{
		{"secret", Finding{RuleID: "SEC-001", Severity: SeverityHigh}, true},
		{"info finding of another rule", Finding{RuleID: "IAC-309", Severity: SeverityInfo}, true},
		{"impacting dependency", Finding{RuleID: "VULN-001", Metadata: map[string]string{"applicability": "impacting"}}, true},
		{"undetermined dependency", Finding{RuleID: "VULN-001", Metadata: map[string]string{"applicability": "undetermined"}}, true},
		{"dependency without a verdict", Finding{RuleID: "VULN-001"}, true},
		{"not impacting dependency", Finding{RuleID: "VULN-001", Metadata: map[string]string{"applicability": "not_impacting"}}, false},
		{"not impacting on a non-dependency rule", Finding{RuleID: "SEC-001", Metadata: map[string]string{"applicability": "not_impacting"}}, true},
	}
	for _, tc := range cases {
		if got := tc.f.GatesByDefault(); got != tc.want {
			t.Errorf("%s: GatesByDefault = %v, want %v", tc.name, got, tc.want)
		}
	}
}
