package ai

import "testing"

// The project-scoped MCP configuration Claude Code reads is `.mcp.json`. It was
// matched only as `mcp.json`, so the file was inventoried as one opaque
// component and its servers and their tool exposure were absent.
func TestDotMCPJSONIsReadLikeMCPJSON(t *testing.T) {
	content := []byte(`{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"],"env":{"TOKEN":"hunter2"}}}}`)
	for _, path := range []string{"mcp.json", ".mcp.json", "team.mcp.json", ".cursor/mcp.json"} {
		comps := extractComponents(path, content)
		if len(comps) != 1 || comps[0].Type != "mcp_server" || comps[0].Name != "fs" {
			t.Errorf("%s: components = %+v, want the fs server", path, comps)
			continue
		}
		d := comps[0].Details
		if d["command"] != "npx" || d["args"] != "-y @modelcontextprotocol/server-filesystem /" {
			t.Errorf("%s: details = %v, want the launch command", path, d)
		}
		for k, v := range d {
			if v == "hunter2" || k == "env" {
				t.Errorf("%s: the environment block leaked into the inventory: %v", path, d)
			}
		}
		sets := extractToolPermissions(path, content, nil)
		if len(sets) == 0 || sets[0].Server != "fs" {
			t.Errorf("%s: tool matrix = %+v, want the fs server", path, sets)
		}
	}
	if isMCPConfigName("notmcp.json") || isMCPConfigName("mcp.json.bak") {
		t.Error("unrelated names must not be treated as MCP configs")
	}
}

func TestInventoryReadsClientSpecificServerKeys(t *testing.T) {
	vs := []byte(`{"servers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@1.0.0"]}}}`)
	comps := extractComponents(".vscode/mcp.json", vs)
	if len(comps) != 1 || comps[0].Type != "mcp_server" || comps[0].Name != "fs" {
		t.Fatalf(".vscode/mcp.json components = %+v", comps)
	}
	if sets := extractToolPermissions(".vscode/mcp.json", vs, nil); len(sets) != 1 || sets[0].Server != "fs" {
		t.Errorf("tool matrix for .vscode/mcp.json = %+v", sets)
	}
	// Counterexample: `servers` anywhere else is not MCP.
	if comps := extractComponents("mcp.json", vs); len(comps) != 1 || comps[0].Type != "mcp_config" {
		t.Errorf("root mcp.json must not read `servers`: %+v", comps)
	}
	zed := []byte(`{"context_servers":{"z":{"command":{"path":"npx","args":["-y","x-mcp"]}}}}`)
	if comps := extractComponents(".zed/settings.json", zed); len(comps) != 1 || comps[0].Details["command"] != "npx" {
		t.Errorf("zed components = %+v", comps)
	}
	// An editor settings file with no server table is not inventoried as MCP.
	if comps := extractComponents(".zed/settings.json", []byte(`{"theme":"One"}`)); len(comps) != 0 {
		t.Errorf("plain zed settings inventoried: %+v", comps)
	}
}
