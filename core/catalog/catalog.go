// Package catalog provides a central registry of all built-in rule metadata
// across all Nox analyzers. It aggregates rules from secrets, AI, and IaC
// analyzers into a single lookup map keyed by rule ID.
//
// Compliance framework mapping (CIS, PCI-DSS, SOC2, NIST-800-53, HIPAA,
// OWASP-Top-10, FedRAMP, ISO 27001, GDPR, etc.) lives in the GRC plugin
// rather than core, so the catalog reports per-rule metadata only and
// downstream consumers join against the plugin's framework data.
package catalog

import (
	"github.com/nox-hq/nox/core/analyzers/agentflow"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/data"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/analyzers/fileperms"
	"github.com/nox-hq/nox/core/analyzers/hardening"
	"github.com/nox-hq/nox/core/analyzers/iac"
	"github.com/nox-hq/nox/core/analyzers/memsafe"
	"github.com/nox-hq/nox/core/analyzers/provenance"
	"github.com/nox-hq/nox/core/analyzers/secrets"
	"github.com/nox-hq/nox/core/analyzers/slop"
	"github.com/nox-hq/nox/core/analyzers/taintflow"
	"github.com/nox-hq/nox/core/analyzers/variants"
	"github.com/nox-hq/nox/core/analyzers/weakcrypto"
	"github.com/nox-hq/nox/core/rules"
)

// RuleMeta provides extended metadata for a built-in rule.
type RuleMeta struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	CWE         string   `json:"cwe,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Catalog returns the complete set of built-in rule metadata keyed by rule ID.
func Catalog() map[string]RuleMeta {
	cat := make(map[string]RuleMeta)

	// Aggregate rules from all analyzers.
	for _, rs := range allRuleSets() {
		for _, r := range rs.Rules() {
			cat[r.ID] = metaFromRule(r)
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
		slop.NewAnalyzer().Rules(),
		variants.NewAnalyzer().Rules(),
		provenance.NewAnalyzer().Rules(),
		// These six publish rules too, and were missing: their findings appeared
		// in scans while `nox rules` and the MCP rules tool denied the rules
		// existed, and any metadata join by rule ID came back empty for them.
		agentflow.NewAnalyzer().Rules(),
		taintflow.NewAnalyzer().Rules(),
		weakcrypto.NewAnalyzer().Rules(),
		hardening.NewAnalyzer().Rules(),
		memsafe.NewAnalyzer().Rules(),
		fileperms.NewAnalyzer().Rules(),
	}
}

func metaFromRule(r *rules.Rule) RuleMeta {
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
