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
}

// NewInventory returns an empty inventory with the current schema version.
func NewInventory() *Inventory {
	return &Inventory{
		SchemaVersion: "1.0.0",
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

	builtinRules := []rules.Rule{
		// -----------------------------------------------------------------
		// Prompt / RAG boundary rules
		// -----------------------------------------------------------------
		{
			ID:          "AI-001",
			Version:     "1.0",
			Description: "Prompt injection boundary marker missing or weak",
			Severity:    findings.SeverityHigh,
			Confidence:  findings.ConfidenceMedium,
			MatcherType: "regex",
			Pattern:     `(?i)(user_input|user_message|user_query)\s*[:=]\s*[^{]*\+\s*(prompt|system_prompt|instructions)`,
			Tags:        []string{"ai", "prompt-injection"},
			Metadata:    map[string]string{"cwe": "CWE-77"},
			Remediation: "Use structured message arrays with distinct system/user roles instead of string concatenation. Apply input sanitisation before injecting user content into prompts.",
			References:  []string{"https://cwe.mitre.org/data/definitions/77.html", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			ID:          "AI-002",
			Version:     "1.0",
			Description: "Direct string concatenation of user input into prompt template",
			Severity:    findings.SeverityHigh,
			Confidence:  findings.ConfidenceHigh,
			MatcherType: "regex",
			Pattern: `(?i)(f["']|\.format\(|%s).*?` +
				`(user_input|user_message|user_query|user_prompt)`,
			Tags:        []string{"ai", "prompt-injection"},
			Metadata:    map[string]string{"cwe": "CWE-77"},
			Remediation: "Use parameterised prompt templates or structured message arrays. Never concatenate untrusted input directly into prompt strings.",
			References:  []string{"https://cwe.mitre.org/data/definitions/77.html", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			ID:          "AI-003",
			Version:     "1.0",
			Description: "RAG context injected without sanitisation boundary",
			Severity:    findings.SeverityMedium,
			Confidence:  findings.ConfidenceMedium,
			MatcherType: "regex",
			Pattern:     `(?i)(context|retrieved_docs?|rag_results?|search_results?)\s*[:=].*\+\s*(prompt|system|messages)`,
			Tags:        []string{"ai", "rag", "prompt-injection"},
			Metadata:    map[string]string{"cwe": "CWE-77"},
			Remediation: "Wrap retrieved documents in explicit boundary markers (e.g., XML tags). Sanitise retrieved content and limit its influence on system instructions.",
			References:  []string{"https://cwe.mitre.org/data/definitions/77.html"},
		},

		// -----------------------------------------------------------------
		// Unsafe MCP tool exposure
		// -----------------------------------------------------------------
		{
			ID:           "AI-004",
			Version:      "1.0",
			Description:  "MCP server exposes file system write tool without restrictions",
			Severity:     findings.SeverityCritical,
			Confidence:   findings.ConfidenceMedium,
			MatcherType:  "regex",
			Pattern:      `(?i)("name"\s*:\s*"(write|delete|remove|exec|execute|run|shell)")|("tool"\s*:\s*"(write|delete|remove|exec|execute|run|shell)")`,
			FilePatterns: []string{"mcp.json", "*.json"},
			Tags:         []string{"ai", "mcp", "tool-exposure"},
			Metadata:     map[string]string{"cwe": "CWE-284"},
			Remediation: "Restrict MCP tools to read-only operations. Use an explicit allowlist in your mcp.json configuration and remove write/execute capabilities.",
			References:  []string{"https://cwe.mitre.org/data/definitions/284.html", "https://modelcontextprotocol.io/docs/concepts/tools"},
		},
		{
			ID:           "AI-005",
			Version:      "1.0",
			Description:  "MCP configuration allows all tools without allowlist",
			Severity:     findings.SeverityHigh,
			Confidence:   findings.ConfidenceMedium,
			MatcherType:  "regex",
			Pattern:      `(?i)"allow(ed)?_?tools"\s*:\s*\[\s*"\*"\s*\]`,
			FilePatterns: []string{"mcp.json", "*.json", "*.yaml", "*.yml"},
			Tags:         []string{"ai", "mcp", "tool-exposure"},
			Metadata:     map[string]string{"cwe": "CWE-284"},
			Remediation: "Replace the wildcard '*' with an explicit list of allowed tool names. Follow the principle of least privilege for agent tool access.",
			References:  []string{"https://cwe.mitre.org/data/definitions/284.html"},
		},

		// -----------------------------------------------------------------
		// Insecure logging of prompts / responses
		// -----------------------------------------------------------------
		{
			ID:          "AI-006",
			Version:     "1.0",
			Description: "Prompt or LLM response logged without redaction",
			Severity:    findings.SeverityMedium,
			Confidence:  findings.ConfidenceMedium,
			MatcherType: "regex",
			Pattern: `(?i)(log|logger|logging|print|console\.log|fmt\.Print)\S*\(.*?` +
				`(prompt|system_message|completion|response\.text|response\.content|chat_response)`,
			Tags:        []string{"ai", "logging", "data-exposure"},
			Metadata:    map[string]string{"cwe": "CWE-532"},
			Remediation: "Redact or truncate prompt and response content before logging. Use structured logging with PII-safe fields. Avoid logging full LLM interactions in production.",
			References:  []string{"https://cwe.mitre.org/data/definitions/532.html"},
		},
		{
			ID:          "AI-007",
			Version:     "1.0",
			Description: "LLM API key or token logged or printed",
			Severity:    findings.SeverityHigh,
			Confidence:  findings.ConfidenceHigh,
			MatcherType: "regex",
			Pattern: `(?i)(log|logger|print|console\.log|fmt\.Print)\S*\(.*?` +
				`(openai_api_key|anthropic_api_key|api_key|bearer_token)`,
			Tags:        []string{"ai", "logging", "secrets"},
			Metadata:    map[string]string{"cwe": "CWE-532"},
			Remediation: "Never log API keys or tokens. Use secret masking in your logging framework. Store credentials in environment variables and reference them by name only.",
			References:  []string{"https://cwe.mitre.org/data/definitions/532.html"},
		},

		// -----------------------------------------------------------------
		// Unpinned or unverified models
		// -----------------------------------------------------------------
		{
			ID:          "AI-008",
			Version:     "1.0",
			Description: "Model reference without version pin or hash",
			Severity:    findings.SeverityMedium,
			Confidence:  findings.ConfidenceLow,
			MatcherType: "regex",
			Pattern:     `(?i)(model\s*[:=]\s*["'])(gpt-4|gpt-3\.5|claude|gemini|llama|mistral|command)["']`,
			Tags:        []string{"ai", "model", "supply-chain"},
			Metadata:    map[string]string{"cwe": "CWE-829"},
			Remediation: "Pin model references to specific versions (e.g., 'gpt-4-0613' instead of 'gpt-4'). This ensures reproducible behaviour and protects against unintended model changes.",
			References:  []string{"https://cwe.mitre.org/data/definitions/829.html"},
		},
	}

	for _, r := range builtinRules {
		rs.Add(r)
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
		}
	}

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
