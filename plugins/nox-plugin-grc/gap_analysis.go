package main

import (
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// AssessmentResult holds the result of a framework compliance assessment.
type AssessmentResult struct {
	Framework       string
	CoveragePercent float64
	CoveredControls []string
	CriticalGaps    []ControlGap
	coveredMap      map[string]bool
}

// HasEvidenceFor checks if a control has evidence in the assessment.
func (a *AssessmentResult) HasEvidenceFor(controlID string) bool {
	if a.coveredMap == nil {
		return false
	}
	return a.coveredMap[controlID]
}

// ControlGap represents a missing control.
type ControlGap struct {
	ControlID   string
	Description string
	Priority    string
}

// GapReport holds a comprehensive gap analysis for a framework.
type GapReport struct {
	Framework         string
	CoveragePercent   float64
	CoveredCount      int
	TotalControls     int
	UncoveredControls []ControlGap
}

// assessFramework evaluates how well the current findings cover a framework's controls.
func assessFramework(fw Framework, findings []*pluginv1.Finding) *AssessmentResult {
	ruleSet := buildRuleSet(findings)

	covered := make(map[string]bool)
	var gaps []ControlGap

	for _, ctrl := range fw.Controls {
		if isControlCovered(ctrl, ruleSet) {
			covered[ctrl.ID] = true
		} else if ctrl.Priority == "high" {
			gaps = append(gaps, ControlGap{
				ControlID:   ctrl.ID,
				Description: ctrl.Description,
				Priority:    ctrl.Priority,
			})
		}
	}

	var coveredList []string
	for id := range covered {
		coveredList = append(coveredList, id)
	}

	pct := 0.0
	if len(fw.Controls) > 0 {
		pct = float64(len(covered)) / float64(len(fw.Controls)) * 100
	}

	return &AssessmentResult{
		Framework:       fw.ID,
		CoveragePercent: pct,
		CoveredControls: coveredList,
		CriticalGaps:    gaps,
		coveredMap:      covered,
	}
}

// generateGapReport creates a comprehensive gap report for a framework.
func generateGapReport(fw Framework, findings []*pluginv1.Finding) *GapReport {
	ruleSet := buildRuleSet(findings)

	var uncovered []ControlGap
	coveredCount := 0

	for _, ctrl := range fw.Controls {
		if isControlCovered(ctrl, ruleSet) {
			coveredCount++
		} else {
			uncovered = append(uncovered, ControlGap{
				ControlID:   ctrl.ID,
				Description: ctrl.Description,
				Priority:    ctrl.Priority,
			})
		}
	}

	pct := 0.0
	if len(fw.Controls) > 0 {
		pct = float64(coveredCount) / float64(len(fw.Controls)) * 100
	}

	return &GapReport{
		Framework:         fw.ID,
		CoveragePercent:   pct,
		CoveredCount:      coveredCount,
		TotalControls:     len(fw.Controls),
		UncoveredControls: uncovered,
	}
}

// buildRuleSet creates a set of rule IDs from findings.
func buildRuleSet(findings []*pluginv1.Finding) map[string]bool {
	set := make(map[string]bool)
	for _, f := range findings {
		set[f.GetRuleId()] = true
	}
	return set
}

// isControlCovered checks if at least one of the control's mapped nox rules has findings.
func isControlCovered(ctrl Control, ruleSet map[string]bool) bool {
	for _, ruleID := range ctrl.NoxRules {
		if ruleSet[ruleID] {
			return true
		}
	}
	return false
}
