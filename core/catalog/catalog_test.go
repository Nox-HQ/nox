package catalog

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func TestCatalogContainsAllRules(t *testing.T) {
	cat := Catalog()

	// We expect 1553 built-in rules across all analyzers (SEC + DATA + AI
	// + IAC + VULN + SLOP-001 slopsquatting + VARIANT-001..006 CVE variants
	// + PROV-001/002 provenance). AI includes AI-PI-* (LLM01),
	// AI-EMBED-* (LLM06), MCP-* families: MCP-001..008 (server
	// hardening), MCP-009..014 (tool poisoning, OWASP MCP03),
	// MCP-016..021 (authorization & token safety, OWASP MCP07), and
	// MCP-022 (shadow/remote server, OWASP MCP09); and AGENT-001..006
	// (agent-config artifacts: rule-file injection, permission bypass,
	// wildcard tool grants, exfiltration directives, unauthenticated A2A
	// cards, DXT command injection). MCP-015 (rug pull, core/mcppin) and
	// MCP-023/024 (shadowing, core/mcpshadow) are emitted relationally
	// outside the regex engine.
	if got := len(cat); got != 1553 {
		t.Errorf("Catalog() returned %d rules, want 1553", got)
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
		{"IAC-007", "Kubernetes pod running as privileged"},
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
