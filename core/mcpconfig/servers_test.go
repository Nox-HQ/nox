package mcpconfig

import (
	"encoding/json"
	"testing"
)

func TestServersKeyIsChosenByPath(t *testing.T) {
	cases := map[string]string{
		".vscode/mcp.json":                               "servers",
		"repo/.vscode/mcp.json":                          "servers",
		`repo\.vscode\mcp.json`:                          "servers",
		"Library/Application Support/Code/User/mcp.json": "servers",
		".zed/settings.json":                             "context_servers",
		".config/zed/settings.json":                      "context_servers",
		".cursor/mcp.json":                               "mcpServers",
		".mcp.json":                                      "mcpServers",
		"claude_desktop_config.json":                     "mcpServers",
		".codeium/windsurf/mcp_config.json":              "mcpServers",
		"mcp.json":                                       "mcpServers",
		"deploy/servers.json":                            "mcpServers",
		"settings.json":                                  "mcpServers",
	}
	for p, want := range cases {
		if got := ServersKey(p); got != want {
			t.Errorf("ServersKey(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestParseServersAt(t *testing.T) {
	vs := []byte(`{"inputs":[],"servers":{"a":{"command":"npx"},"b":{"url":"https://x"}}}`)
	got, err := ParseServersAt(".vscode/mcp.json", vs)
	if err != nil || len(got) != 2 {
		t.Fatalf("vscode servers = %v, %v", got, err)
	}
	// Counterexample: the same bytes anywhere else are not an MCP config.
	for _, p := range []string{"inventory.json", "deploy/hosts.json", "mcp.json", ".cursor/mcp.json"} {
		if got, err := ParseServersAt(p, vs); err != nil || len(got) != 0 {
			t.Errorf("%s: unrelated `servers` read as MCP: %v %v", p, got, err)
		}
	}
	// And a `servers` list in a .vscode/mcp.json is not a server table.
	if got, err := ParseServersAt(".vscode/mcp.json", []byte(`{"servers":[1]}`)); err != nil || got != nil {
		t.Errorf("list-valued servers = %v, %v", got, err)
	}
	// Malformed stays an error.
	if _, err := ParseServersAt(".vscode/mcp.json", []byte(`{"servers":`)); err == nil {
		t.Error("malformed JSON must be an error")
	}
	z, err := ParseServersAt(".zed/settings.json", []byte(`{"theme":"x","context_servers":{"z":{"command":{"path":"npx","args":["-y","p"]}}}}`))
	if err != nil || len(z) != 1 {
		t.Fatalf("zed = %v %v", z, err)
	}
	l, err := ParseLaunch(z["z"])
	if err != nil || l.Command != "npx" || len(l.Args) != 2 {
		t.Errorf("zed launch = %+v %v", l, err)
	}
	l, _ = ParseLaunch(json.RawMessage(`{"command":"uvx","args":["m"]}`))
	if l.Command != "uvx" || l.Args[0] != "m" {
		t.Errorf("string launch = %+v", l)
	}
}
