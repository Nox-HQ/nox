package lsp

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestSeverityToLSP(t *testing.T) {
	cases := map[findings.Severity]int{
		findings.SeverityCritical: severityError,
		findings.SeverityHigh:     severityError,
		findings.SeverityMedium:   severityWarning,
		findings.SeverityLow:      severityInformation,
		findings.SeverityInfo:     severityHint,
		findings.Severity("wat"):  severityHint,
	}
	for sev, want := range cases {
		if got := severityToLSP(sev); got != want {
			t.Errorf("severityToLSP(%q) = %d, want %d", sev, got, want)
		}
	}
}

func TestFindingToDiagnosticClamping(t *testing.T) {
	f := findings.Finding{
		RuleID:   "SEC-001",
		Severity: findings.SeverityHigh,
		Message:  "boom",
		Location: findings.Location{
			StartLine: 1, EndLine: 0, // 1-based; EndLine defaults below StartLine
			StartColumn: 5, EndColumn: 5, // zero-width -> widen to StartColumn+1
		},
	}
	d := findingToDiagnostic(&f)
	if d.Range.Start.Line != 0 || d.Range.End.Line != 0 {
		t.Errorf("lines = %d..%d, want 0..0", d.Range.Start.Line, d.Range.End.Line)
	}
	if d.Range.Start.Character != 5 || d.Range.End.Character != 6 {
		t.Errorf("chars = %d..%d, want 5..6", d.Range.Start.Character, d.Range.End.Character)
	}
	if d.Code != "SEC-001" || d.Source != "nox" || d.Message != "boom" {
		t.Errorf("unexpected fields: %+v", d)
	}
}

func TestFindingToDiagnosticNegativeClampAndMultiline(t *testing.T) {
	f := findings.Finding{
		RuleID:   "X-1",
		Severity: findings.SeverityLow,
		Location: findings.Location{
			StartLine: 0, EndLine: 4, // StartLine-1 = -1 -> clamp to 0; end uses max(0,4)-1=3
			StartColumn: -3, EndColumn: 2, // start clamps to 0, end 2 > 0 kept
		},
	}
	d := findingToDiagnostic(&f)
	if d.Range.Start.Line != 0 {
		t.Errorf("start line = %d, want 0", d.Range.Start.Line)
	}
	if d.Range.End.Line != 3 {
		t.Errorf("end line = %d, want 3", d.Range.End.Line)
	}
	if d.Range.Start.Character != 0 || d.Range.End.Character != 2 {
		t.Errorf("chars = %d..%d, want 0..2", d.Range.Start.Character, d.Range.End.Character)
	}
}

func TestFindingsToDiagnosticsSortStable(t *testing.T) {
	fs := []findings.Finding{
		{RuleID: "B", Severity: findings.SeverityHigh, Location: findings.Location{StartLine: 3, StartColumn: 1, EndColumn: 2}},
		{RuleID: "A", Severity: findings.SeverityHigh, Location: findings.Location{StartLine: 1, StartColumn: 4, EndColumn: 5}},
		{RuleID: "C", Severity: findings.SeverityHigh, Location: findings.Location{StartLine: 1, StartColumn: 4, EndColumn: 5}},
		{RuleID: "A2", Severity: findings.SeverityHigh, Location: findings.Location{StartLine: 1, StartColumn: 2, EndColumn: 3}},
	}
	got := findingsToDiagnostics(fs)
	wantOrder := []string{"A2", "A", "C", "B"} // line1 col2, line1 col4 (A<C), line3
	if len(got) != len(wantOrder) {
		t.Fatalf("len = %d, want %d", len(got), len(wantOrder))
	}
	for i, code := range wantOrder {
		if got[i].Code != code {
			t.Errorf("order[%d] = %q, want %q (full: %+v)", i, got[i].Code, code, got)
		}
	}
}
