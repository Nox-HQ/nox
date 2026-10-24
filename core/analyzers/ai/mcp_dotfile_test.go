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
