package ai

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/degrade"
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
	// Descriptions maps tool name -> description string captured at
	// registration time. Empty entries omitted; populated by the
	// agent-lattice extractor for languages where description appears
	// inline (LangChain, LangChain.js, agent-go).
	Descriptions map[string]string `json:"descriptions,omitempty"`
	// Capabilities maps tool name -> normalised capability tags
	// (file_read, http_request, shell_exec, ...). Same source as the
	// AI-AGENT-* lattice findings.
	Capabilities map[string][]string `json:"capabilities,omitempty"`
}

// extractToolPermissions parses MCP and agent configs for tool permission
// matrices. deg (may be nil) receives a visible degradation when a file that is
// structurally an MCP config fails to parse, so a broken config does not quietly
// contribute an empty matrix.
func extractToolPermissions(path string, content []byte, deg *degrade.Degradations) []ToolPermissionSet {
	var sets []ToolPermissionSet
	fileName := baseName(path)

	if fileName == "mcp.json" {
		sets = append(sets, extractMCPToolPermissions(path, content, deg)...)
	}

	// Agent config files with tools arrays
	sets = append(sets, extractAgentToolPermissions(path, content)...)

	// Source-code-level tool registrations with description + capability
	// metadata captured by the agent-lattice extractor.
	if set := extractAgentLatticeToolSet(path, content); set != nil {
		sets = append(sets, *set)
	}

	return sets
}

// extractAgentLatticeToolSet returns a ToolPermissionSet populated from
// the agent-lattice tool extractor when the file registers any tools.
// Captures description and capability tags so AIBOM consumers can
// audit description-vs-implementation drift.
func extractAgentLatticeToolSet(path string, content []byte) *ToolPermissionSet {
	tools := extractTools(path, content)
	if len(tools) == 0 {
		return nil
	}
	set := &ToolPermissionSet{
		Agent:        baseName(path),
		Path:         path,
		Tools:        make([]string, 0, len(tools)),
		Descriptions: map[string]string{},
		Capabilities: map[string][]string{},
	}
	for i := range tools {
		t := &tools[i]
		set.Tools = append(set.Tools, t.name)
		if t.description != "" {
			set.Descriptions[t.name] = t.description
		}
		if len(t.tags) > 0 {
			caps := make([]string, 0, len(t.tags))
			for _, tag := range t.tags {
				caps = append(caps, string(tag))
			}
			set.Capabilities[t.name] = caps
		}
	}
	return set
}

func extractMCPToolPermissions(path string, content []byte, deg *degrade.Degradations) []ToolPermissionSet {
	var config struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(content, &config); err != nil {
		// A file named mcp.json that will not parse is not "no tools here" — it
		// is a config whose tool exposure we could not read. Returning nil made
		// it indistinguishable from a genuinely toolless config, so a rogue
		// server with a deliberately-broken definition dropped off the matrix.
		deg.Add(degrade.MCP,
			fmt.Sprintf("%s could not be parsed: %v", path, err),
			"the MCP tool permission matrix was not built for this file; its servers and their tool exposure are absent from the AI inventory")
		return nil
	}

	// Deterministic order — see the note in extractMCPComponents.
	names := make([]string, 0, len(config.MCPServers))
	for serverName := range config.MCPServers {
		names = append(names, serverName)
	}
	sort.Strings(names)

	var sets []ToolPermissionSet
	for _, serverName := range names {
		raw := config.MCPServers[serverName]
		var serverConfig struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		}
		// A server entry that does not decode falls through to Tools=["*"]
		// below (unknown/all tools). That default is the safe direction, but
		// silently applying it hid the fact that we never actually read the
		// server's command/args — surface it so "this server exposes everything"
		// is a reported assumption, not an invisible one.
		if err := json.Unmarshal(raw, &serverConfig); err != nil {
			deg.Add(degrade.MCP,
				fmt.Sprintf("%s: MCP server %q definition could not be parsed: %v", path, serverName, err),
				"this server was recorded as exposing all tools (*) because its definition could not be read; its real command and tool exposure are unknown")
		}

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
	// Source-code files (.py / .js / .ts / .go) are handled by the
	// agent-lattice extractor, which captures tool name + description
	// + capability tags. This legacy regex is kept only for config /
	// data files (yaml, json, toml) where the lattice extractor's
	// language-specific patterns don't apply.
	switch {
	case strings.HasSuffix(path, ".py"),
		strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".jsx"),
		strings.HasSuffix(path, ".ts"), strings.HasSuffix(path, ".tsx"),
		strings.HasSuffix(path, ".mjs"), strings.HasSuffix(path, ".cjs"),
		strings.HasSuffix(path, ".go"):
		return nil
	}

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
