package ai

import (
	"testing"
)

// TestMCPComponents_Deterministic pins the ordering of AI inventory components
// from a multi-server mcp.json.
//
// extractMCPComponents and extractMCPToolPermissions iterated config.MCPServers
// directly, so ai.inventory.json came out in random order run to run —
// violating the project's determinism guarantee for a reproducible artifact.
func TestMCPComponents_Deterministic(t *testing.T) {
	t.Parallel()

	cfg := []byte(`{"mcpServers":{"zeta":{"command":"z"},"alpha":{"command":"a"},"mid":{"command":"m"}}}`)

	var first []string
	for run := 0; run < 20; run++ {
		comps := extractMCPComponents("mcp.json", cfg)
		names := make([]string, len(comps))
		for i := range comps {
			names[i] = comps[i].Name
		}
		if run == 0 {
			first = names
			// It must also be sorted, not merely stable-by-luck.
			for i := 1; i < len(names); i++ {
				if names[i-1] > names[i] {
					t.Errorf("components not sorted: %v", names)
				}
			}
			continue
		}
		if len(names) != len(first) {
			t.Fatalf("run %d length differs", run)
		}
		for i := range names {
			if names[i] != first[i] {
				t.Fatalf("run %d order differs: %v vs %v", run, names, first)
			}
		}
	}
}
