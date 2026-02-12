package ai

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Connection represents a connection between AI components.
type Connection struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"` // "tool_access", "model_call", "data_flow"
}

// ToolPermissionSet represents the tools available to an agent or MCP server.
type ToolPermissionSet struct {
	Agent  string   `json:"agent"`
	Server string   `json:"server,omitempty"`
	Tools  []string `json:"tools"`
	Path   string   `json:"path"`
}

// extractToolPermissions parses MCP and agent configs for tool permission matrices.
func extractToolPermissions(path string, content []byte) []ToolPermissionSet {
	var sets []ToolPermissionSet
	fileName := baseName(path)

	if fileName == "mcp.json" {
		sets = append(sets, extractMCPToolPermissions(path, content)...)
	}

	// Agent config files with tools arrays
	sets = append(sets, extractAgentToolPermissions(path, content)...)

	return sets
}

func extractMCPToolPermissions(path string, content []byte) []ToolPermissionSet {
	var config struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil
	}

	var sets []ToolPermissionSet
	for serverName, raw := range config.MCPServers {
		var serverConfig struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		}
		_ = json.Unmarshal(raw, &serverConfig)

		set := ToolPermissionSet{
			Agent:  "mcp_client",
			Server: serverName,
			Path:   path,
		}
		// Extract tool names from args if they mention tool restrictions
		for _, arg := range serverConfig.Args {
			if strings.Contains(arg, "tool") {
				set.Tools = append(set.Tools, arg)
			}
		}
		if len(set.Tools) == 0 {
			set.Tools = []string{"*"} // unknown/all tools
		}
		sets = append(sets, set)
	}
	return sets
}

func extractAgentToolPermissions(path string, content []byte) []ToolPermissionSet {
	var sets []ToolPermissionSet
	text := string(content)

	// Pattern: tools: ["tool1", "tool2"] or allowed_tools: [...]
	toolsRe := regexp.MustCompile(`(?i)(tools|allowed_tools|capabilities)\s*[:=]\s*\[([^\]]+)\]`)
	for _, m := range toolsRe.FindAllStringSubmatch(text, -1) {
		toolList := extractQuotedStrings(m[2])
		if len(toolList) > 0 {
			sets = append(sets, ToolPermissionSet{
				Agent: baseName(path),
				Tools: toolList,
				Path:  path,
			})
		}
	}

	return sets
}

// extractConnections builds a connection graph from discovered components.
func extractConnections(components []Component, toolSets []ToolPermissionSet) []Connection {
	var conns []Connection

	// Connect MCP servers to their tools
	for _, ts := range toolSets {
		if ts.Server != "" {
			conns = append(conns, Connection{
				From: ts.Agent,
				To:   ts.Server,
				Type: "tool_access",
			})
		}
	}

	// Connect agents to models they reference
	agentPaths := make(map[string]bool)
	modelPaths := make(map[string]bool)
	for _, c := range components {
		switch c.Type {
		case "agent":
			agentPaths[c.Path] = true
		case "model_reference":
			modelPaths[c.Path] = true
		}
	}

	// If agent and model are in the same file, connect them
	for _, c := range components {
		if c.Type == "agent" {
			for _, m := range components {
				if m.Type == "model_reference" && m.Path == c.Path {
					conns = append(conns, Connection{
						From: c.Name,
						To:   m.Name,
						Type: "model_call",
					})
				}
			}
		}
	}

	return conns
}

func extractQuotedStrings(s string) []string {
	re := regexp.MustCompile(`['"]([^'"]+)['"]`)
	var result []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		result = append(result, m[1])
	}
	return result
}
