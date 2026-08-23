package report

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func dataFinding(rule, file string) findings.Finding {
	return findings.Finding{RuleID: rule, Location: findings.Location{FilePath: file}}
}

func TestBuildDataSensitivityReport(t *testing.T) {
	ff := []findings.Finding{
		dataFinding("DATA-001", "a.go"),
		dataFinding("DATA-001", "a.go"), // duplicate file for the same rule
		dataFinding("DATA-001", "b.go"),
		dataFinding("DATA-002", "b.go"),
		dataFinding("SEC-001", "c.go"), // non-DATA, must be ignored
	}
	rep := BuildDataSensitivityReport(ff, func(id string) string { return "desc:" + id })

	if rep.TotalFindings != 4 {
		t.Errorf("TotalFindings = %d, want 4 (SEC excluded)", rep.TotalFindings)
	}
	if len(rep.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rep.Rules))
	}
	// Sorted by rule id; DATA-001 first with 3 findings across 2 unique files.
	if rep.Rules[0].RuleID != "DATA-001" || rep.Rules[0].Count != 3 || len(rep.Rules[0].Files) != 2 {
		t.Errorf("DATA-001 stats wrong: %+v", rep.Rules[0])
	}
	if rep.Rules[0].Description != "desc:DATA-001" {
		t.Errorf("description not injected: %q", rep.Rules[0].Description)
	}
	// Affected files are the union, sorted and deduped.
	if len(rep.AffectedFiles) != 2 || rep.AffectedFiles[0] != "a.go" || rep.AffectedFiles[1] != "b.go" {
		t.Errorf("affected files wrong: %v", rep.AffectedFiles)
	}
}

func TestBuildDataSensitivityReportEmptyAndNilDescribe(t *testing.T) {
	rep := BuildDataSensitivityReport(nil, nil)
	if rep.TotalFindings != 0 || len(rep.Rules) != 0 {
		t.Errorf("empty input should yield an empty report: %+v", rep)
	}
	// A nil describe falls back to the rule id.
	rep = BuildDataSensitivityReport([]findings.Finding{dataFinding("DATA-001", "x")}, nil)
	if rep.Rules[0].Description != "DATA-001" {
		t.Errorf("nil describe should fall back to rule id, got %q", rep.Rules[0].Description)
	}
}
