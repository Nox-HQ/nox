package policy

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestEvaluate_AllNewAboveThreshold(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityHigh}
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityCritical, Status: findings.StatusNew},
	}

	r := Evaluate(cfg, ff)
	if r.Pass {
		t.Fatal("expected fail")
	}
	if r.ExitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", r.ExitCode)
	}
}

func TestEvaluate_AllNewBelowThreshold(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityHigh}
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityLow, Status: findings.StatusNew},
	}

	r := Evaluate(cfg, ff)
	if !r.Pass {
		t.Fatal("expected pass")
	}
}

func TestEvaluate_NoFindings(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityHigh}
	r := Evaluate(cfg, nil)
	if !r.Pass {
		t.Fatal("expected pass")
	}
	if r.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", r.ExitCode)
	}
}

func TestEvaluate_BaselinedWarnMode(t *testing.T) {
	cfg := Config{
		FailOn:       findings.SeverityHigh,
		BaselineMode: BaselineModeWarn,
	}
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityCritical, Status: findings.StatusBaselined},
	}

	r := Evaluate(cfg, ff)
	if !r.Pass {
		t.Fatal("expected pass in warn mode")
	}
	if len(r.Warnings) == 0 {
		t.Fatal("expected warnings for baselined findings")
	}
}

func TestEvaluate_BaselinedStrictMode(t *testing.T) {
	cfg := Config{
		FailOn:       findings.SeverityHigh,
		BaselineMode: BaselineModeStrict,
	}
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityCritical, Status: findings.StatusBaselined},
	}

	r := Evaluate(cfg, ff)
	if r.Pass {
		t.Fatal("expected fail in strict mode")
	}
}

func TestEvaluate_MixedSeverities(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityMedium}
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityLow},
		{RuleID: "SEC-002", Severity: findings.SeverityInfo},
	}

	r := Evaluate(cfg, ff)
	if !r.Pass {
		t.Fatal("expected pass — all below medium threshold")
	}
}

func TestEvaluate_NoThreshold_AnyFindingFails(t *testing.T) {
	cfg := Config{}
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityInfo},
	}

	r := Evaluate(cfg, ff)
	if r.Pass {
		t.Fatal("expected fail with no threshold and any finding")
	}
}

func TestEvaluate_SummaryContainsPass(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityCritical}
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityLow},
	}

	r := Evaluate(cfg, ff)
	if r.Summary == "" {
		t.Fatal("expected non-empty summary")
	}
}

func TestMeetsThreshold(t *testing.T) {
	tests := []struct {
		severity  findings.Severity
		threshold findings.Severity
		want      bool
	}{
		{findings.SeverityCritical, findings.SeverityHigh, true},
		{findings.SeverityHigh, findings.SeverityHigh, true},
		{findings.SeverityMedium, findings.SeverityHigh, false},
		{findings.SeverityLow, findings.SeverityCritical, false},
		{findings.SeverityInfo, findings.SeverityInfo, true},
	}

	for _, tt := range tests {
		got := meetsThreshold(tt.severity, tt.threshold)
		if got != tt.want {
			t.Errorf("meetsThreshold(%s, %s) = %v, want %v", tt.severity, tt.threshold, got, tt.want)
		}
	}
}
