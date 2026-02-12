// Package compliance provides mapping between nox security rules and
// compliance framework controls (CIS, PCI-DSS, SOC2, NIST-800-53, HIPAA,
// OWASP Top 10). This enables compliance-filtered scan output.
package compliance

import "strings"

// Framework identifies a compliance framework.
type Framework string

// Supported compliance frameworks.
const (
	CIS       Framework = "CIS"
	PCIDSS    Framework = "PCI-DSS"
	SOC2      Framework = "SOC2"
	NIST80053 Framework = "NIST-800-53"
	HIPAA     Framework = "HIPAA"
	OWASPTop  Framework = "OWASP-Top-10"
)

// SupportedFrameworks lists all frameworks supported by nox.
var SupportedFrameworks = []Framework{CIS, PCIDSS, SOC2, NIST80053, HIPAA, OWASPTop}

// FrameworkControl is a single control within a compliance framework.
type FrameworkControl struct {
	Framework Framework `json:"framework"`
	ControlID string    `json:"control_id"`
	Title     string    `json:"title"`
}

// Mapping associates a nox rule ID with its compliance framework controls.
type Mapping struct {
	RuleID     string
	Frameworks []FrameworkControl
}

// GetMappings returns all rule-to-framework mappings keyed by rule ID.
func GetMappings() map[string][]FrameworkControl {
	return complianceData()
}

// FilterByFramework returns only mappings for the specified framework.
func FilterByFramework(fw Framework, mappings map[string][]FrameworkControl) map[string][]FrameworkControl {
	fwUpper := Framework(strings.ToUpper(string(fw)))
	result := make(map[string][]FrameworkControl)
	for ruleID, controls := range mappings {
		var filtered []FrameworkControl
		for _, c := range controls {
			if Framework(strings.ToUpper(string(c.Framework))) == fwUpper {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) > 0 {
			result[ruleID] = filtered
		}
	}
	return result
}

// RulesForFramework returns all rule IDs that map to the specified framework.
func RulesForFramework(fw Framework) []string {
	filtered := FilterByFramework(fw, GetMappings())
	ruleIDs := make([]string, 0, len(filtered))
	for ruleID := range filtered {
		ruleIDs = append(ruleIDs, ruleID)
	}
	return ruleIDs
}

// FrameworkReport generates a compliance summary for a given framework
// from a set of triggered rule IDs.
type FrameworkReport struct {
	Framework     Framework          `json:"framework"`
	TotalControls int                `json:"total_controls"`
	Violations    []ControlViolation `json:"violations"`
}

// ControlViolation represents a compliance control that was violated.
type ControlViolation struct {
	ControlID string   `json:"control_id"`
	Title     string   `json:"title"`
	RuleIDs   []string `json:"rule_ids"`
}

// GenerateReport creates a compliance report for a framework given triggered rule IDs.
func GenerateReport(fw Framework, triggeredRuleIDs []string) *FrameworkReport {
	mappings := FilterByFramework(fw, GetMappings())

	// Build set of triggered rules.
	triggered := make(map[string]struct{}, len(triggeredRuleIDs))
	for _, id := range triggeredRuleIDs {
		triggered[id] = struct{}{}
	}

	// Collect all controls for this framework and check violations.
	controlRules := make(map[string][]string) // controlID -> []ruleID
	controlTitle := make(map[string]string)   // controlID -> title
	for ruleID, controls := range mappings {
		if _, ok := triggered[ruleID]; !ok {
			continue
		}
		for _, c := range controls {
			controlRules[c.ControlID] = append(controlRules[c.ControlID], ruleID)
			controlTitle[c.ControlID] = c.Title
		}
	}

	var violations []ControlViolation
	for ctrlID, ruleIDs := range controlRules {
		violations = append(violations, ControlViolation{
			ControlID: ctrlID,
			Title:     controlTitle[ctrlID],
			RuleIDs:   ruleIDs,
		})
	}

	// Count total unique controls for this framework.
	allControls := make(map[string]struct{})
	for _, controls := range mappings {
		for _, c := range controls {
			allControls[c.ControlID] = struct{}{}
		}
	}

	return &FrameworkReport{
		Framework:     fw,
		TotalControls: len(allControls),
		Violations:    violations,
	}
}
