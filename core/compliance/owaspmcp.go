// Package compliance maps Nox rules to external security frameworks. The first
// framework hosted here is the OWASP MCP Top 10, the emerging compliance
// reference for MCP security. Mapping lives in core (not the GRC plugin)
// because MCP coverage is a first-class Nox positioning surface and the
// mapping must be emitted in the core SARIF report for registries and GitHub
// Code Scanning to see standards alignment.
package compliance

import "strings"

// OWASPMCPControl is a single OWASP MCP Top 10 control.
type OWASPMCPControl struct {
	ID    string // e.g. "MCP03"
	Title string
}

// owaspMCPTop10 is the OWASP MCP Top 10 (2025) control catalog.
var owaspMCPTop10 = []OWASPMCPControl{
	{"MCP01", "Token Mismanagement & Secret Exposure"},
	{"MCP02", "Privilege Escalation via Scope Creep"},
	{"MCP03", "Tool Poisoning"},
	{"MCP04", "Supply Chain Attacks & Dependency Tampering"},
	{"MCP05", "Command Injection & Execution"},
	{"MCP06", "Prompt Injection via Contextual Payloads"},
	{"MCP07", "Insufficient Authentication & Authorization"},
	{"MCP08", "Lack of Audit & Telemetry"},
	{"MCP09", "Shadow MCP Servers"},
	{"MCP10", "Context Injection & Over-Sharing"},
}

var owaspMCPByID = func() map[string]OWASPMCPControl {
	m := make(map[string]OWASPMCPControl, len(owaspMCPTop10))
	for _, c := range owaspMCPTop10 {
		m[c.ID] = c
	}
	return m
}()

// mcpRuleControls maps each MCP-family rule to its primary OWASP MCP control.
// Rules MCP-009+ also carry an owasp-mcpNN tag; the explicit table covers the
// older MCP-001..008 family (which predates the tags) and the relationally
// emitted rules (MCP-015, MCP-023, MCP-024) that never pass through the rule
// engine's tag list.
var mcpRuleControls = map[string]string{
	"MCP-001": "MCP05", // shell interpreter invocation
	"MCP-002": "MCP02", // broad home/root path scope
	"MCP-003": "MCP02", // dangerously-permissive flags
	"MCP-004": "MCP01", // embedded secret in env
	"MCP-005": "MCP08", // missing tool description (auditability)
	"MCP-006": "MCP07", // plaintext HTTP transport
	"MCP-007": "MCP04", // remote code fetch at startup
	"MCP-008": "MCP08", // unbounded handler (no rate limit/audit)
	"MCP-009": "MCP03",
	"MCP-010": "MCP03",
	"MCP-011": "MCP03",
	"MCP-012": "MCP03",
	"MCP-013": "MCP03",
	"MCP-014": "MCP03",
	"MCP-015": "MCP04", // rug pull
	"MCP-016": "MCP07",
	"MCP-017": "MCP07",
	"MCP-018": "MCP07",
	"MCP-019": "MCP07",
	"MCP-020": "MCP07",
	"MCP-021": "MCP07",
	"MCP-022": "MCP09",
	"MCP-023": "MCP09", // server-name shadowing
	"MCP-024": "MCP09", // tool-name shadowing
}

// Framework returns the OWASP MCP Top 10 control catalog.
func Framework() []OWASPMCPControl {
	out := make([]OWASPMCPControl, len(owaspMCPTop10))
	copy(out, owaspMCPTop10)
	return out
}

// Control looks up an OWASP MCP control by ID. The second return is false when
// the ID is unknown.
func Control(id string) (OWASPMCPControl, bool) {
	c, ok := owaspMCPByID[id]
	return c, ok
}

// ControlForRule returns the OWASP MCP control ID for a rule, resolving first
// from the explicit MCP rule table and falling back to an owasp-mcpNN tag.
// Returns "" when the rule has no MCP mapping.
func ControlForRule(ruleID string, tags []string) string {
	if c, ok := mcpRuleControls[ruleID]; ok {
		return c
	}
	return controlFromTags(tags)
}

// controlFromTags extracts an OWASP MCP control from an "owasp-mcpNN" tag.
func controlFromTags(tags []string) string {
	for _, t := range tags {
		lower := strings.ToLower(t)
		if suffix, ok := strings.CutPrefix(lower, "owasp-mcp"); ok && len(suffix) == 2 {
			id := "MCP" + suffix
			if _, known := owaspMCPByID[id]; known {
				return id
			}
		}
	}
	return ""
}
