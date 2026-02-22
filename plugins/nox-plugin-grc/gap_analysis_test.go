package main

import (
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

func TestAssessFrameworkFullCoverage(t *testing.T) {
	fw := Framework{
		ID: "test-fw", Name: "Test", Threshold: 50,
		Controls: []Control{
			{ID: "C1", Description: "Control 1", Priority: "high", NoxRules: []string{"SEC-001"}},
			{ID: "C2", Description: "Control 2", Priority: "medium", NoxRules: []string{"VULN-001"}},
		},
	}

	findings := []*pluginv1.Finding{
		{RuleId: "SEC-001", Severity: sdk.SeverityHigh},
		{RuleId: "VULN-001", Severity: sdk.SeverityMedium},
	}

	result := assessFramework(fw, findings)

	if result.CoveragePercent != 100.0 {
		t.Errorf("expected 100%% coverage, got %.1f%%", result.CoveragePercent)
	}
	if len(result.CriticalGaps) != 0 {
		t.Errorf("expected 0 critical gaps, got %d", len(result.CriticalGaps))
	}
}

func TestAssessFrameworkPartialCoverage(t *testing.T) {
	fw := Framework{
		ID: "test-fw", Name: "Test", Threshold: 50,
		Controls: []Control{
			{ID: "C1", Description: "Control 1", Priority: "high", NoxRules: []string{"SEC-001"}},
			{ID: "C2", Description: "Control 2", Priority: "high", NoxRules: []string{"VULN-001"}},
			{ID: "C3", Description: "Control 3", Priority: "medium", NoxRules: []string{"DATA-001"}},
		},
	}

	findings := []*pluginv1.Finding{
		{RuleId: "SEC-001", Severity: sdk.SeverityHigh},
	}

	result := assessFramework(fw, findings)

	expectedPct := 100.0 / 3.0
	if result.CoveragePercent < expectedPct-0.1 || result.CoveragePercent > expectedPct+0.1 {
		t.Errorf("expected ~%.1f%% coverage, got %.1f%%", expectedPct, result.CoveragePercent)
	}
	if len(result.CriticalGaps) != 1 {
		t.Errorf("expected 1 critical gap (C2), got %d", len(result.CriticalGaps))
	}
	if len(result.CriticalGaps) > 0 && result.CriticalGaps[0].ControlID != "C2" {
		t.Errorf("expected gap for C2, got %q", result.CriticalGaps[0].ControlID)
	}
}

func TestAssessFrameworkNoFindings(t *testing.T) {
	fw := Framework{
		ID: "test-fw", Name: "Test", Threshold: 50,
		Controls: []Control{
			{ID: "C1", Description: "Control 1", Priority: "high", NoxRules: []string{"SEC-001"}},
		},
	}

	result := assessFramework(fw, nil)

	if result.CoveragePercent != 0.0 {
		t.Errorf("expected 0%% coverage, got %.1f%%", result.CoveragePercent)
	}
	if len(result.CriticalGaps) != 1 {
		t.Errorf("expected 1 critical gap, got %d", len(result.CriticalGaps))
	}
}

func TestAssessFrameworkNoControls(t *testing.T) {
	fw := Framework{
		ID: "test-fw", Name: "Test", Threshold: 50,
		Controls: nil,
	}

	result := assessFramework(fw, nil)

	if result.CoveragePercent != 0.0 {
		t.Errorf("expected 0%% coverage for empty framework, got %.1f%%", result.CoveragePercent)
	}
}

func TestGenerateGapReport(t *testing.T) {
	fw := Framework{
		ID: "test-fw", Name: "Test", Threshold: 50,
		Controls: []Control{
			{ID: "C1", Description: "Control 1", Priority: "high", NoxRules: []string{"SEC-001"}},
			{ID: "C2", Description: "Control 2", Priority: "medium", NoxRules: []string{"VULN-001"}},
		},
	}

	findings := []*pluginv1.Finding{
		{RuleId: "SEC-001"},
	}

	report := generateGapReport(fw, findings)

	if report.CoveredCount != 1 {
		t.Errorf("expected 1 covered, got %d", report.CoveredCount)
	}
	if report.TotalControls != 2 {
		t.Errorf("expected 2 total, got %d", report.TotalControls)
	}
	if len(report.UncoveredControls) != 1 {
		t.Errorf("expected 1 uncovered, got %d", len(report.UncoveredControls))
	}
	if report.CoveragePercent != 50.0 {
		t.Errorf("expected 50%% coverage, got %.1f%%", report.CoveragePercent)
	}
}

func TestHasEvidenceFor(t *testing.T) {
	result := &AssessmentResult{
		coveredMap: map[string]bool{
			"C1": true,
			"C3": true,
		},
	}

	if !result.HasEvidenceFor("C1") {
		t.Error("expected C1 to have evidence")
	}
	if result.HasEvidenceFor("C2") {
		t.Error("expected C2 to have no evidence")
	}
}

func TestHasEvidenceForNilMap(t *testing.T) {
	result := &AssessmentResult{}
	if result.HasEvidenceFor("C1") {
		t.Error("expected false for nil map")
	}
}

func TestCollectEvidenceMatchesControls(t *testing.T) {
	fw := Framework{
		ID: "test-fw", Name: "Test",
		Controls: []Control{
			{ID: "C1", NoxRules: []string{"SEC-001", "SEC-002"}},
			{ID: "C2", NoxRules: []string{"VULN-001"}},
		},
	}

	findings := []*pluginv1.Finding{
		{RuleId: "SEC-001", Location: &pluginv1.Location{FilePath: "auth.go", StartLine: 10}},
		{RuleId: "OTHER-001"},
	}

	evidence := collectEvidence(fw, "", findings)

	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence item, got %d", len(evidence))
	}
	if evidence[0].ControlID != "C1" {
		t.Errorf("expected evidence for C1, got %q", evidence[0].ControlID)
	}
	if evidence[0].File != "auth.go" {
		t.Errorf("expected file auth.go, got %q", evidence[0].File)
	}
}

func TestCollectEvidenceByControlID(t *testing.T) {
	fw := Framework{
		ID: "test-fw", Name: "Test",
		Controls: []Control{
			{ID: "C1", NoxRules: []string{"SEC-001"}},
			{ID: "C2", NoxRules: []string{"VULN-001"}},
		},
	}

	findings := []*pluginv1.Finding{
		{RuleId: "SEC-001"},
		{RuleId: "VULN-001"},
	}

	evidence := collectEvidence(fw, "C2", findings)

	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence item for C2, got %d", len(evidence))
	}
	if evidence[0].ControlID != "C2" {
		t.Errorf("expected evidence for C2, got %q", evidence[0].ControlID)
	}
}
