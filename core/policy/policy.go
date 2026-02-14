// Package policy evaluates scan findings against configurable thresholds to
// determine pass/fail outcomes for CI pipelines.
package policy

import (
	"fmt"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// BaselineMode controls how baselined findings affect policy evaluation.
type BaselineMode string

const (
	// BaselineModeStrict counts baselined findings toward failure.
	BaselineModeStrict BaselineMode = "strict"
	// BaselineModeWarn treats baselined findings as warnings only.
	BaselineModeWarn BaselineMode = "warn"
	// BaselineModeOff disables baseline handling in policy evaluation.
	BaselineModeOff BaselineMode = "off"
)

// Config defines the policy evaluation parameters.
type Config struct {
	FailOn       findings.Severity `yaml:"fail_on"`
	WarnOn       findings.Severity `yaml:"warn_on"`
	BaselineMode BaselineMode      `yaml:"baseline_mode"`
}

// Result holds the outcome of a policy evaluation.
type Result struct {
	Pass      bool
	ExitCode  int
	New       []findings.Finding
	Baselined []findings.Finding
	Warnings  []string
	Summary   string
}

// severityRank maps severity levels to numeric ranks for comparison.
// Lower rank = more severe.
var severityRank = map[findings.Severity]int{
	findings.SeverityCritical: 0,
	findings.SeverityHigh:     1,
	findings.SeverityMedium:   2,
	findings.SeverityLow:      3,
	findings.SeverityInfo:     4,
}

// Evaluate applies policy rules to the given findings and returns the result.
func Evaluate(cfg Config, all []findings.Finding) *Result {
	r := &Result{Pass: true, ExitCode: 0}

	for i := range all {
		finding := all[i]
		switch finding.Status {
		case findings.StatusBaselined:
			r.Baselined = append(r.Baselined, finding)
		default:
			r.New = append(r.New, finding)
		}
	}

	// Check new findings against fail threshold.
	if cfg.FailOn != "" {
		maxNew := maxSeverity(r.New)
		if maxNew != "" && meetsThreshold(maxNew, cfg.FailOn) {
			r.Pass = false
			r.ExitCode = 1
		}
	} else if len(r.New) > 0 {
		// No explicit threshold: any new finding fails.
		r.Pass = false
		r.ExitCode = 1
	}

	// Handle baselined findings per mode.
	switch cfg.BaselineMode {
	case BaselineModeStrict:
		if cfg.FailOn != "" {
			maxBaselined := maxSeverity(r.Baselined)
			if maxBaselined != "" && meetsThreshold(maxBaselined, cfg.FailOn) {
				r.Pass = false
				r.ExitCode = 1
			}
		} else if len(r.Baselined) > 0 {
			r.Pass = false
			r.ExitCode = 1
		}
	case BaselineModeWarn:
		if len(r.Baselined) > 0 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%d baselined finding(s) still present", len(r.Baselined)))
		}
	}

	// Check warnings threshold.
	if cfg.WarnOn != "" {
		for i := range r.New {
			finding := r.New[i]
			if meetsThreshold(finding.Severity, cfg.WarnOn) && !meetsThreshold(finding.Severity, cfg.FailOn) {
				r.Warnings = append(r.Warnings, fmt.Sprintf("warning: %s finding %s in %s",
					finding.Severity, finding.RuleID, finding.Location.FilePath))
			}
		}
	}

	// Build summary.
	var parts []string
	parts = append(parts, fmt.Sprintf("%d new", len(r.New)))
	if len(r.Baselined) > 0 {
		parts = append(parts, fmt.Sprintf("%d baselined", len(r.Baselined)))
	}
	if r.Pass {
		r.Summary = fmt.Sprintf("policy: pass (%s)", strings.Join(parts, ", "))
	} else {
		r.Summary = fmt.Sprintf("policy: fail (%s)", strings.Join(parts, ", "))
	}

	return r
}

// meetsThreshold returns true if severity is at or above the threshold.
func meetsThreshold(severity, threshold findings.Severity) bool {
	sr, ok1 := severityRank[severity]
	tr, ok2 := severityRank[threshold]
	if !ok1 || !ok2 {
		return false
	}
	return sr <= tr
}

// maxSeverity returns the most severe severity in the given findings.
func maxSeverity(ff []findings.Finding) findings.Severity {
	best := findings.Severity("")
	bestRank := 999
	for i := range ff {
		finding := ff[i]
		r, ok := severityRank[finding.Severity]
		if ok && r < bestRank {
			bestRank = r
			best = finding.Severity
		}
	}
	return best
}
