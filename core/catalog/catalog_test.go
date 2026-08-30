package catalog

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestCatalogContainsAllRules(t *testing.T) {
	cat := Catalog()

	// We expect 1553 built-in rules across all analyzers (SEC + DATA + AI
	// + IAC + VULN + SLOP-001/002 slopsquatting + VARIANT-001..006 CVE variants
	// + PROV-001/002 provenance). AI includes AI-PI-* (LLM01),
	// AI-EMBED-* (LLM08), MCP-* families: MCP-001..008 (server
	// hardening), MCP-009..014 (tool poisoning, OWASP MCP03),
	// MCP-016..021 (authorization & token safety, OWASP MCP07), and
	// MCP-022 (shadow/remote server, OWASP MCP09); and AGENT-001..006
	// (agent-config artifacts: rule-file injection, permission bypass,
	// wildcard tool grants, exfiltration directives, unauthenticated A2A
	// cards, DXT command injection). MCP-015 (rug pull, core/mcppin) and
	// MCP-023/024 (shadowing, core/mcpshadow) are emitted relationally
	// outside the regex engine.
	// 1547 = 1553 minus the six duplicate secret rules merged away
	// (SEC-152, SEC-451, SEC-452, SEC-470, SEC-558, SEC-673).
	// 1528 = 1547 minus the 19 redundant bare-connection-scheme secret rules
	// deleted (SEC-356..SEC-370 and SEC-430..SEC-433): they fired on
	// password-less URLs, and the credential-aware DSN rules SEC-073/074/076
	// already cover connection strings carrying userinfo credentials.
	// 1529 = 1528 plus SLOP-002 (predictive slopsquat-target match, emitted by
	// the slop analyzer when a verified blocklist feed is loaded).
	// 1519 = 1529 minus the ten duplicate IaC rules retired in #394 (IAC-237,
	// IAC-283, IAC-287, IAC-291, IAC-292, IAC-310, IAC-312, IAC-321, IAC-333,
	// IAC-337): each reported a condition an older rule already reported, and
	// each lives on as an alias on that rule so existing waivers keep matching.
	// 1537 = 1519 plus the 18 rules from the six analyzers that publish rules
	// but were never registered in allRuleSets: AGENTFLOW-001/002, TAINT-001..007
	// and TAINT-AI-001, CRYPTO-001/002, HARDEN-001/002, PERM-001/002 and
	// MEMSAFE-001. Their findings appeared in scans while `nox rules` and the
	// MCP rules tool denied the rules existed.
	//
	// 1537 -> 1535 removed two secrets rules whose pattern was a bare
	// character class plus a file-level keyword: SEC-542 (retired into
	// SEC-087, which detects the same credential by requiring the assignment)
	// and SEC-524 (an Azure subscription ID is not a credential).
	if got := len(cat); got != 1535 {
		t.Errorf("Catalog() returned %d rules, want 1535", got)
	}
}

func TestCatalogRulesHaveRemediation(t *testing.T) {
	cat := Catalog()

	for id, meta := range cat {
		if meta.Remediation == "" {
			t.Errorf("rule %s has no remediation text", id)
		}
	}
}

func TestCatalogRulesHaveDescription(t *testing.T) {
	cat := Catalog()

	for id, meta := range cat {
		if meta.Description == "" {
			t.Errorf("rule %s has no description", id)
		}
		if meta.Severity == "" {
			t.Errorf("rule %s has no severity", id)
		}
	}
}

func TestCatalogLookup(t *testing.T) {
	cat := Catalog()

	tests := []struct {
		id   string
		want string
	}{
		{"SEC-001", "AWS Access Key ID detected"},
		{"SEC-002", "AWS Secret Access Key detected"},
		{"AI-004", "MCP server exposes file system write tool without restrictions"},
		// Reworded when IAC-007 absorbed IAC-065's privileged branch (ECS)
		// and IAC-237 (Kustomize) in #394 -- it is no longer k8s-only.
		{"IAC-007", "Container runs in privileged mode"},
	}

	for _, tt := range tests {
		meta, ok := cat[tt.id]
		if !ok {
			t.Errorf("rule %s not found in catalog", tt.id)
			continue
		}
		if meta.Description != tt.want {
			t.Errorf("rule %s description = %q, want %q", tt.id, meta.Description, tt.want)
		}
	}
}

func TestCatalog_AllRulesHaveValidSeverityAndConfidence(t *testing.T) {
	for id, meta := range Catalog() {
		if !findings.Severity(meta.Severity).IsValid() {
			t.Errorf("rule %s has invalid severity %q", id, meta.Severity)
		}
		if !findings.Confidence(meta.Confidence).IsValid() {
			t.Errorf("rule %s has invalid confidence %q", id, meta.Confidence)
		}
	}
}
