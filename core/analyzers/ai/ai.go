// Package ai implements AI security scanning and inventory extraction. It wraps
// the core/rules engine with built-in rules that detect common AI/LLM security
// risks such as prompt injection boundaries, unsafe MCP tool exposure, insecure
// prompt/response logging, and unpinned models. It also extracts an inventory
// of AI components discovered in the workspace.
package ai

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Component represents a single AI component discovered in the workspace.
type Component struct {
	// Name is a human-readable identifier for the component.
	Name string `json:"name"`
	// Type classifies the component (e.g., "prompt", "agent", "mcp_config", "model_reference").
	Type string `json:"type"`
	// Path is the file path relative to the workspace root.
	Path string `json:"path"`
	// Details holds additional metadata extracted from the component.
	Details map[string]string `json:"details,omitempty"`
}

// Inventory is the collection of AI components discovered during scanning.
// It is serialised to ai.inventory.json.
type Inventory struct {
	// SchemaVersion identifies the inventory format.
	SchemaVersion string `json:"schema_version"`
	// Components is the list of discovered AI components.
	Components []Component `json:"components"`
	// ConnectionGraph maps connections between AI components.
	ConnectionGraph []Connection `json:"connection_graph,omitempty"`
	// ModelProvenance lists ML model references found in the codebase.
	ModelProvenance []ModelReference `json:"model_provenance,omitempty"`
	// PromptTemplates lists prompt templates discovered in the codebase.
	PromptTemplates []PromptTemplate `json:"prompt_templates,omitempty"`
	// ToolMatrix lists tool permission sets for agents and MCP servers.
	ToolMatrix []ToolPermissionSet `json:"tool_permission_matrix,omitempty"`
}

// NewInventory returns an empty inventory with the current schema version.
func NewInventory() *Inventory {
	return &Inventory{
		SchemaVersion: "2.0.0",
		Components:    []Component{},
	}
}

// Add appends a component to the inventory.
func (inv *Inventory) Add(c Component) {
	inv.Components = append(inv.Components, c)
}

// JSON returns the inventory as pretty-printed JSON bytes.
func (inv *Inventory) JSON() ([]byte, error) {
	return json.MarshalIndent(inv, "", "  ")
}

// WriteFile writes the inventory to the given file path.
func (inv *Inventory) WriteFile(path string) error {
	data, err := inv.JSON()
	if err != nil {
		return fmt.Errorf("marshalling inventory: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// Analyzer wraps a rules.Engine pre-loaded with AI security rules and also
// extracts an inventory of AI components.
type Analyzer struct {
	engine *rules.Engine
}

// NewAnalyzer creates an Analyzer with built-in AI security rules.
func NewAnalyzer() *Analyzer {
	rs := rules.NewRuleSet()
	aiRules := builtinAIRules()
	for i := range aiRules {
		rs.Add(aiRules[i])
	}
	return &Analyzer{
		engine: rules.NewEngine(rs),
	}
}

// Rules returns the analyzer's RuleSet for catalog aggregation.
func (a *Analyzer) Rules() *rules.RuleSet { return a.engine.Rules() }

// ScanFile delegates to the underlying rules engine to scan the given file
// content and returns any AI security findings.
func (a *Analyzer) ScanFile(path string, content []byte) ([]findings.Finding, error) {
	return a.engine.ScanFile(path, content)
}

// ScanArtifacts reads each artifact file from disk, scans it for AI security
// issues, and collects findings. It also builds an AI component inventory from
// artifacts classified as AIComponent.
func (a *Analyzer) ScanArtifacts(artifacts []discovery.Artifact) (*findings.FindingSet, *Inventory, error) {
	fs := findings.NewFindingSet()
	inv := NewInventory()

	for _, artifact := range artifacts {
		content, err := os.ReadFile(artifact.AbsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("reading artifact %s: %w", artifact.Path, err)
		}

		// Scan for AI security rule violations.
		results, err := a.ScanFile(artifact.Path, content)
		if err != nil {
			return nil, nil, fmt.Errorf("scanning artifact %s: %w", artifact.Path, err)
		}
		for _, f := range results {
			fs.Add(f)
		}

		// Extract inventory entries from AI component artifacts.
		if artifact.Type == discovery.AIComponent {
			components := extractComponents(artifact.Path, content)
			for _, c := range components {
				inv.Add(c)
			}

			// Extract model references.
			modelRefs := extractModelReferences(artifact.Path, content)
			inv.ModelProvenance = append(inv.ModelProvenance, modelRefs...)

			// Extract prompt templates.
			promptTmpls := extractPromptTemplates(artifact.Path, content)
			inv.PromptTemplates = append(inv.PromptTemplates, promptTmpls...)

			// Extract tool permissions.
			toolPerms := extractToolPermissions(artifact.Path, content)
			inv.ToolMatrix = append(inv.ToolMatrix, toolPerms...)
		}
	}

	// Build connection graph from discovered components and tool permissions.
	inv.ConnectionGraph = extractConnections(inv.Components, inv.ToolMatrix)

	fs.Deduplicate()
	return fs, inv, nil
}

// extractComponents inspects the content of an AI component artifact and
// returns inventory entries. It dispatches based on file name and content
// structure.
func extractComponents(path string, content []byte) []Component {
	name := baseName(path)

	switch {
	case name == "mcp.json":
		return extractMCPComponents(path, content)
	case hasSuffix(name, ".prompt") || hasSuffix(name, ".prompt.md"):
		return []Component{{
			Name: name,
			Type: "prompt",
			Path: path,
		}}
	default:
		// Generic AI component (under /agents/ or /prompts/ directory).
		return []Component{{
			Name: name,
			Type: classifyByPath(path),
			Path: path,
		}}
	}
}

// extractMCPComponents parses an mcp.json file and extracts one inventory
// entry per configured MCP server.
func extractMCPComponents(path string, content []byte) []Component {
	// Try to parse as JSON with mcpServers key.
	var config struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(content, &config); err != nil {
		// If unparseable, return a single generic entry.
		return []Component{{
			Name: "mcp.json",
			Type: "mcp_config",
			Path: path,
		}}
	}

	if len(config.MCPServers) == 0 {
		return []Component{{
			Name: "mcp.json",
			Type: "mcp_config",
			Path: path,
		}}
	}

	var components []Component
	for serverName := range config.MCPServers {
		components = append(components, Component{
			Name:    serverName,
			Type:    "mcp_server",
			Path:    path,
			Details: map[string]string{"server": serverName},
		})
	}
	return components
}

// classifyByPath returns a component type based on path segments.
func classifyByPath(path string) string {
	if containsSegment(path, "agents") {
		return "agent"
	}
	if containsSegment(path, "prompts") {
		return "prompt"
	}
	return "ai_component"
}

// containsSegment reports whether path contains the given directory segment.
func containsSegment(path, segment string) bool {
	parts := splitPath(path)
	for _, p := range parts {
		if p == segment {
			return true
		}
	}
	return false
}

// splitPath splits a slash-separated path into segments.
func splitPath(path string) []string {
	var parts []string
	for _, p := range split(path, '/') {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// split splits s by sep and returns the parts.
func split(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// baseName returns the last segment of a slash-separated path.
func baseName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

// hasSuffix reports whether s ends with suffix.
func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
