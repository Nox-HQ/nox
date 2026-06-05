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

// Regression: an inline-suppressed High must not fail the fail-on gate.
// Previously suppressed findings fell through to r.New and tripped the gate.
func TestEvaluate_SuppressedHighDoesNotFailGate(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityHigh}
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityHigh, Status: findings.StatusSuppressed},
	}
	r := Evaluate(cfg, ff)
	if !r.Pass {
		t.Fatal("suppressed High must not fail the gate")
	}
	if len(r.New) != 0 {
		t.Errorf("suppressed finding must not be counted as new, got %d", len(r.New))
	}
	if len(r.Suppressed) != 1 {
		t.Errorf("expected 1 suppressed finding, got %d", len(r.Suppressed))
	}
}

func TestEvaluate_VEXFixedExcludedFromGate(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityHigh}
	ff := []findings.Finding{
		{RuleID: "VULN-001", Severity: findings.SeverityCritical, Status: findings.StatusVEXFixed},
	}
	r := Evaluate(cfg, ff)
	if !r.Pass {
		t.Fatal("VEX-fixed finding must not fail the gate")
	}
}

// A suppressed High alongside a real Low: gate passes (Low is below High), and
// the suppressed High is not silently promoted into the gate.
func TestEvaluate_SuppressedHighWithActiveLow(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityHigh}
	ff := []findings.Finding{
		{RuleID: "SEC-001", Severity: findings.SeverityHigh, Status: findings.StatusSuppressed},
		{RuleID: "SEC-002", Severity: findings.SeverityLow, Status: findings.StatusNew},
	}
	r := Evaluate(cfg, ff)
	if !r.Pass {
		t.Fatal("only an active Low remains; gate should pass")
	}
	if len(r.New) != 1 || r.New[0].RuleID != "SEC-002" {
		t.Errorf("expected only the active Low in New, got %+v", r.New)
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
