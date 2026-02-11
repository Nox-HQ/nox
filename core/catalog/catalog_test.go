package catalog

import (
	"testing"
)

func TestCatalogContainsAllRules(t *testing.T) {
	cat := Catalog()

	// We expect 155 built-in rules: 86 SEC + 18 AI + 50 IAC + 1 VULN.
	if got := len(cat); got != 155 {
		t.Errorf("Catalog() returned %d rules, want 155", got)
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
