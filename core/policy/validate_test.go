package policy

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// TestConfig_Validate covers the gate-disabling bug: an unrecognized fail_on
// value made meetsThreshold return false for every severity, so a scan with
// critical findings passed. Validation must reject these at load time.
func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	valid := []Config{
		{},
		{FailOn: "critical"},
		{FailOn: "high", WarnOn: "low"},
		{BaselineMode: BaselineModeStrict},
		{Budget: map[findings.Severity]int{"high": 2}},
	}
	for _, c := range valid {
		if err := c.Validate(); err != nil {
			t.Errorf("expected %+v to be valid, got %v", c, err)
		}
	}

	invalid := []struct {
		cfg  Config
		want string
	}{
		{Config{FailOn: "High"}, "fail_on"},      // capitalized
		{Config{FailOn: "HIGH"}, "fail_on"},      // uppercase
		{Config{FailOn: "critical "}, "fail_on"}, // trailing space
		{Config{FailOn: "criticl"}, "fail_on"},   // typo
		{Config{FailOn: "error"}, "fail_on"},     // wrong vocabulary
		{Config{WarnOn: "Medium"}, "warn_on"},    // capitalized warn
		{Config{BaselineMode: "strictt"}, "baseline_mode"},
		{Config{Budget: map[findings.Severity]int{"High": 1}}, "budget"},
	}
	for _, tc := range invalid {
		err := tc.cfg.Validate()
		if err == nil {
			t.Errorf("expected %+v to be rejected, got nil", tc.cfg)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("expected error to mention %q, got %v", tc.want, err)
		}
	}
}

// TestEvaluate_InvalidThresholdWouldBypass documents WHY validation matters: it
// pins the dangerous runtime behaviour that Validate() now prevents from ever
// being reached. An invalid threshold silently passes a critical finding.
func TestEvaluate_InvalidThresholdWouldBypass(t *testing.T) {
	t.Parallel()

	crit := []findings.Finding{{Severity: findings.SeverityCritical, Status: findings.StatusNew}}

	// The exact string an operator would typo. Evaluate does not validate — the
	// load-time guard does — so this still demonstrates the bypass a caller
	// would hit if they skipped Validate.
	bypass := Evaluate(Config{FailOn: "High"}, crit)
	if bypass.ExitCode == 0 {
		t.Log("confirmed: an unvalidated invalid fail_on passes a critical finding (exit 0) — this is why Validate must run at load")
	}

	// The valid lowercase form gates correctly.
	gated := Evaluate(Config{FailOn: "high"}, crit)
	if gated.ExitCode != 1 {
		t.Errorf("valid fail_on=high should gate a critical finding, got exit %d", gated.ExitCode)
	}
}
