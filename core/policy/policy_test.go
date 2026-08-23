package policy

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// newN returns n new findings of the given severity.
func newN(sev findings.Severity, n int) []findings.Finding {
	ff := make([]findings.Finding, n)
	for i := range ff {
		ff[i] = findings.Finding{RuleID: "SEC-001", Severity: sev, Status: findings.StatusNew}
	}
	return ff
}

func TestEvaluate_Budget(t *testing.T) {
	cases := []struct {
		name     string
		cfg      Config
		findings []findings.Finding
		wantPass bool
	}{
		{
			name:     "within medium budget passes",
			cfg:      Config{FailOn: findings.SeverityMedium, Budget: map[findings.Severity]int{findings.SeverityMedium: 5}},
			findings: newN(findings.SeverityMedium, 5),
			wantPass: true,
		},
		{
			name:     "over medium budget fails",
			cfg:      Config{FailOn: findings.SeverityMedium, Budget: map[findings.Severity]int{findings.SeverityMedium: 5}},
			findings: newN(findings.SeverityMedium, 6),
			wantPass: false,
		},
		{
			name: "budgeted medium ok but any new high still fails (default 0)",
			cfg:  Config{FailOn: findings.SeverityMedium, Budget: map[findings.Severity]int{findings.SeverityMedium: 5}},
			findings: append(newN(findings.SeverityMedium, 2),
				findings.Finding{RuleID: "SEC-002", Severity: findings.SeverityHigh, Status: findings.StatusNew}),
			wantPass: false,
		},
		{
			name:     "below fail_on is never gated regardless of budget",
			cfg:      Config{FailOn: findings.SeverityHigh, Budget: map[findings.Severity]int{findings.SeverityMedium: 0}},
			findings: newN(findings.SeverityMedium, 20),
			wantPass: true,
		},
		{
			name:     "empty budget reproduces the old gate (any new high fails)",
			cfg:      Config{FailOn: findings.SeverityHigh},
			findings: newN(findings.SeverityHigh, 1),
			wantPass: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Evaluate(tc.cfg, tc.findings)
			if r.Pass != tc.wantPass {
				t.Errorf("Pass = %v, want %v (%s)", r.Pass, tc.wantPass, r.Summary)
			}
		})
	}
}

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

// at builds a finding with a location, so the summary has something to name.
func at(sev findings.Severity, rule, file string, line int) findings.Finding {
	return findings.Finding{
		RuleID:   rule,
		Severity: sev,
		Status:   findings.StatusNew,
		Location: findings.Location{FilePath: file, StartLine: line},
	}
}

func TestSummaryNamesWhatFailedTheGate(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityHigh}
	// The shape that caused the confusion: one critical hidden among a crowd
	// of findings that gate nothing.
	all := append(newN(findings.SeverityLow, 70),
		at(findings.SeverityCritical, "SEC-073", "scripts/test-integration.sh", 88))

	r := Evaluate(cfg, all)

	if r.Pass {
		t.Fatalf("a new critical did not fail the gate: %s", r.Summary)
	}
	for _, want := range []string{"SEC-073", "scripts/test-integration.sh:88", "critical"} {
		if !contains(r.Summary, want) {
			t.Errorf("Summary = %q, want it to mention %q", r.Summary, want)
		}
	}
}

func TestSummaryDoesNotNameFindingsThatGateNothing(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityHigh}
	all := append(newN(findings.SeverityLow, 5),
		at(findings.SeverityHigh, "SEC-100", "internal/a.go", 3))

	r := Evaluate(cfg, all)

	// The low findings are the noise that made the old message misleading;
	// naming them would reproduce the problem in a longer form.
	if contains(r.Summary, "SEC-001") {
		t.Errorf("Summary = %q, want only the gating finding named", r.Summary)
	}
}

func TestManyGatingFindingsAreTruncated(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityHigh}
	var all []findings.Finding
	for i := range 10 {
		all = append(all, at(findings.SeverityHigh, "SEC-200", "internal/a.go", i+1))
	}

	r := Evaluate(cfg, all)

	// A wall of findings pushes the summary off the top of a CI log as surely
	// as saying nothing does.
	if !contains(r.Summary, "and 7 more") {
		t.Errorf("Summary = %q, want the tail summarised", r.Summary)
	}
}

func TestAPassingSummaryIsUnchanged(t *testing.T) {
	cfg := Config{FailOn: findings.SeverityHigh}

	r := Evaluate(cfg, newN(findings.SeverityLow, 77))

	if !r.Pass {
		t.Fatalf("low findings failed a high gate: %s", r.Summary)
	}
	// Nothing failed, so there is nothing to name — and a pass should not grow
	// a dash and a list.
	if contains(r.Summary, "—") {
		t.Errorf("Summary = %q, want the passing form untouched", r.Summary)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && strings.Contains(haystack, needle)
}
