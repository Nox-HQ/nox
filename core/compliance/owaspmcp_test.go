package compliance

import (
	"testing"

	"github.com/nox-hq/nox/core/catalog"
)

func TestFramework_TenControls(t *testing.T) {
	if got := len(Framework()); got != 10 {
		t.Fatalf("OWASP MCP Top 10 must have 10 controls, got %d", got)
	}
}

func TestControlForRule_Families(t *testing.T) {
	cases := map[string]string{
		"MCP-009": "MCP03", // tool poisoning
		"MCP-014": "MCP03",
		"MCP-015": "MCP04", // rug pull
		"MCP-016": "MCP07", // auth
		"MCP-021": "MCP07",
		"MCP-022": "MCP09", // shadow
		"MCP-024": "MCP09",
		"MCP-001": "MCP05", // shell exec
		"MCP-007": "MCP04", // supply chain
	}
	for rule, want := range cases {
		if got := ControlForRule(rule, nil); got != want {
			t.Errorf("ControlForRule(%s) = %q, want %q", rule, got, want)
		}
	}
}

func TestControlForRule_FromTag(t *testing.T) {
	// A rule not in the explicit table resolves via its owasp-mcpNN tag.
	if got := ControlForRule("AI-XYZ", []string{"ai", "owasp-mcp03"}); got != "MCP03" {
		t.Errorf("tag-derived control = %q, want MCP03", got)
	}
	if got := ControlForRule("AI-XYZ", []string{"ai", "prompt-injection"}); got != "" {
		t.Errorf("non-MCP rule should have no control, got %q", got)
	}
}

// Every MCP-family rule present in the built-in catalog must map to a valid
// OWASP MCP control. This guards against shipping an MCP rule with no
// standards mapping.
func TestEveryCatalogMCPRuleMapped(t *testing.T) {
	cat := catalog.Catalog()
	for id := range cat {
		if len(id) < 4 || id[:4] != "MCP-" {
			continue
		}
		control := ControlForRule(id, cat[id].Tags)
		if control == "" {
			t.Errorf("catalog rule %s has no OWASP MCP control mapping", id)
			continue
		}
		if _, ok := Control(control); !ok {
			t.Errorf("rule %s maps to unknown control %q", id, control)
		}
	}
}
