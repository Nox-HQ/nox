// Package catalog provides a central registry of all built-in rule metadata
// across all Nox analyzers. It aggregates rules from secrets, AI, and IaC
// analyzers into a single lookup map keyed by rule ID.
package catalog

import (
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/data"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/analyzers/iac"
	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/compliance"
	"github.com/nox-hq/nox/core/rules"
)

// RuleMeta provides extended metadata for a built-in rule.
type RuleMeta struct {
	ID                   string                        `json:"id"`
	Description          string                        `json:"description"`
	Severity             string                        `json:"severity"`
	Confidence           string                        `json:"confidence"`
	CWE                  string                        `json:"cwe,omitempty"`
	Tags                 []string                      `json:"tags,omitempty"`
	Remediation          string                        `json:"remediation,omitempty"`
	References           []string                      `json:"references,omitempty"`
	ComplianceFrameworks []compliance.FrameworkControl `json:"compliance_frameworks,omitempty"`
}

// Catalog returns the complete set of built-in rule metadata keyed by rule ID.
func Catalog() map[string]RuleMeta {
	cat := make(map[string]RuleMeta)
	complianceMappings := compliance.GetMappings()

	// Aggregate rules from all analyzers.
	for _, rs := range allRuleSets() {
		for _, r := range rs.Rules() {
			meta := metaFromRule(r)
			if controls, ok := complianceMappings[r.ID]; ok {
				meta.ComplianceFrameworks = controls
			}
			cat[r.ID] = meta
		}
	}

	return cat
}

// allRuleSets returns the RuleSets from all built-in analyzers.
func allRuleSets() []*rules.RuleSet {
	return []*rules.RuleSet{
		secrets.NewAnalyzer().Rules(),
		data.NewAnalyzer().Rules(),
		ai.NewAnalyzer().Rules(),
		iac.NewAnalyzer().Rules(),
		deps.NewAnalyzer(deps.WithOSVDisabled()).Rules(),
	}
}

func metaFromRule(r rules.Rule) RuleMeta {
	return RuleMeta{
		ID:          r.ID,
		Description: r.Description,
		Severity:    string(r.Severity),
		Confidence:  string(r.Confidence),
		CWE:         r.Metadata["cwe"],
		Tags:        r.Tags,
		Remediation: r.Remediation,
		References:  r.References,
	}
}
