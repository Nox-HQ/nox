package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("creating directory: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return p
}

func findingWithRule(results []findings.Finding, ruleID string) *findings.Finding {
	for _, f := range results {
		if f.RuleID == ruleID {
			return &f
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AI-001: Prompt injection boundary
// ---------------------------------------------------------------------------

func TestDetect_PromptInjectionBoundary(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`user_input = request.body + system_prompt`)

	results, err := a.ScanFile("app.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-001")
	if f == nil {
		t.Fatal("expected AI-001 finding for prompt injection boundary")
	}
	if f.Severity != findings.SeverityHigh {
		t.Fatalf("expected severity high, got %s", f.Severity)
	}
}

// ---------------------------------------------------------------------------
// AI-002: Direct string concatenation into prompt
// ---------------------------------------------------------------------------

func TestDetect_PromptStringConcatenation(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"f-string", `prompt = f"Tell me about {user_input}"`},
		{"format", `prompt = template.format(user_message)`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAnalyzer()
			results, err := a.ScanFile("chat.py", []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			f := findingWithRule(results, "AI-002")
			if f == nil {
				t.Fatalf("expected AI-002 finding for %q", tt.name)
			}
			if f.Severity != findings.SeverityHigh {
				t.Fatalf("expected severity high, got %s", f.Severity)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AI-003: RAG context injection
// ---------------------------------------------------------------------------

func TestDetect_RAGContextInjection(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`context = search_results + prompt`)

	results, err := a.ScanFile("rag.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-003")
	if f == nil {
		t.Fatal("expected AI-003 finding for RAG context injection")
	}
	if f.Severity != findings.SeverityMedium {
		t.Fatalf("expected severity medium, got %s", f.Severity)
	}
}

// ---------------------------------------------------------------------------
// AI-004: MCP unsafe tool exposure
// ---------------------------------------------------------------------------

func TestDetect_MCPUnsafeToolExposure(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`{
  "mcpServers": {
    "filesystem": {
      "tools": [
        {"name": "write", "description": "Write to files"},
        {"name": "read", "description": "Read files"}
      ]
    }
  }
}`)

	results, err := a.ScanFile("mcp.json", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-004")
	if f == nil {
		t.Fatal("expected AI-004 finding for unsafe MCP tool exposure")
	}
	if f.Severity != findings.SeverityCritical {
		t.Fatalf("expected severity critical, got %s", f.Severity)
	}
}

// ---------------------------------------------------------------------------
// AI-005: MCP allows all tools
// ---------------------------------------------------------------------------

func TestDetect_MCPAllowAllTools(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`{
  "allowed_tools": ["*"]
}`)

	results, err := a.ScanFile("mcp.json", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-005")
	if f == nil {
		t.Fatal("expected AI-005 finding for allow-all tools")
	}
	if f.Severity != findings.SeverityHigh {
		t.Fatalf("expected severity high, got %s", f.Severity)
	}
}

// ---------------------------------------------------------------------------
// AI-006: Prompt/response logged without redaction
// ---------------------------------------------------------------------------

func TestDetect_PromptLogged(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"python logging", `logger.info("Prompt: " + prompt)`},
		{"console.log", `console.log(response.content)`},
		{"fmt.Println", `fmt.Println(completion)`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAnalyzer()
			results, err := a.ScanFile("app.py", []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			f := findingWithRule(results, "AI-006")
			if f == nil {
				t.Fatalf("expected AI-006 finding for %q", tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AI-007: API key logged
// ---------------------------------------------------------------------------

func TestDetect_APIKeyLogged(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`logger.debug("Key: " + openai_api_key)`)

	results, err := a.ScanFile("config.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-007")
	if f == nil {
		t.Fatal("expected AI-007 finding for API key logging")
	}
	if f.Severity != findings.SeverityHigh {
		t.Fatalf("expected severity high, got %s", f.Severity)
	}
}

// ---------------------------------------------------------------------------
// AI-008: Unpinned model reference
// ---------------------------------------------------------------------------

func TestDetect_UnpinnedModel(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"gpt-4", `model = "gpt-4"`},
		{"claude", `model: "claude"`},
		{"gemini", `model = "gemini"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAnalyzer()
			results, err := a.ScanFile("config.py", []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			f := findingWithRule(results, "AI-008")
			if f == nil {
				t.Fatalf("expected AI-008 finding for unpinned model %q", tt.name)
			}
			if f.Severity != findings.SeverityMedium {
				t.Fatalf("expected severity medium, got %s", f.Severity)
			}
		})
	}
}

func TestNoDetect_PinnedModel(t *testing.T) {
	a := NewAnalyzer()
	// Pinned model with version — should still match the loose regex but
	// the key point is unpinned ones are caught. A model with a full version
	// like "gpt-4-0613" does NOT match because the pattern expects the
	// model name to be immediately followed by a closing quote.
	content := []byte(`model = "gpt-4-0613"`)

	results, err := a.ScanFile("config.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-008")
	if f != nil {
		t.Fatal("should not flag pinned model with version suffix")
	}
}

// ---------------------------------------------------------------------------
// No false positives on clean files
// ---------------------------------------------------------------------------

func TestNoFalsePositives_CleanPythonFile(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`import openai

def get_response(prompt_text):
    client = openai.Client()
    response = client.chat.completions.create(
        model="gpt-4-turbo-2024-04-09",
        messages=[{"role": "user", "content": prompt_text}],
    )
    return response.choices[0].message.content
`)

	results, err := a.ScanFile("app.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 findings on clean Python file, got %d: %v", len(results), results)
	}
}

// ---------------------------------------------------------------------------
// Inventory: MCP config extraction
// ---------------------------------------------------------------------------

func TestInventory_MCPConfigExtraction(t *testing.T) {
	content := []byte(`{
  "mcpServers": {
    "github": {"command": "gh-mcp"},
    "filesystem": {"command": "fs-mcp"}
  }
}`)

	components := extractMCPComponents("mcp.json", content)
	if len(components) != 2 {
		t.Fatalf("expected 2 MCP server components, got %d", len(components))
	}

	// Sort for deterministic checking.
	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	if components[0].Name != "filesystem" {
		t.Fatalf("expected first component 'filesystem', got %q", components[0].Name)
	}
	if components[0].Type != "mcp_server" {
		t.Fatalf("expected type 'mcp_server', got %q", components[0].Type)
	}
	if components[1].Name != "github" {
		t.Fatalf("expected second component 'github', got %q", components[1].Name)
	}
}

func TestInventory_MCPConfigInvalidJSON(t *testing.T) {
	content := []byte(`not valid json`)

	components := extractMCPComponents("mcp.json", content)
	if len(components) != 1 {
		t.Fatalf("expected 1 generic component for invalid JSON, got %d", len(components))
	}
	if components[0].Type != "mcp_config" {
		t.Fatalf("expected type 'mcp_config', got %q", components[0].Type)
	}
}

func TestInventory_MCPConfigEmptyServers(t *testing.T) {
	content := []byte(`{"mcpServers": {}}`)

	components := extractMCPComponents("mcp.json", content)
	if len(components) != 1 {
		t.Fatalf("expected 1 generic component for empty servers, got %d", len(components))
	}
}

// ---------------------------------------------------------------------------
// Inventory: Prompt file extraction
// ---------------------------------------------------------------------------

func TestInventory_PromptFileExtraction(t *testing.T) {
	components := extractComponents("prompts/summarize.prompt", []byte("Summarize the following..."))
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	if components[0].Type != "prompt" {
		t.Fatalf("expected type 'prompt', got %q", components[0].Type)
	}
	if components[0].Name != "summarize.prompt" {
		t.Fatalf("expected name 'summarize.prompt', got %q", components[0].Name)
	}
}

func TestInventory_PromptMDFileExtraction(t *testing.T) {
	components := extractComponents("prompts/review.prompt.md", []byte("# Review prompt"))
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	if components[0].Type != "prompt" {
		t.Fatalf("expected type 'prompt', got %q", components[0].Type)
	}
}

// ---------------------------------------------------------------------------
// Inventory: Agent file extraction
// ---------------------------------------------------------------------------

func TestInventory_AgentFileExtraction(t *testing.T) {
	components := extractComponents("agents/reviewer.yaml", []byte("name: reviewer"))
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	if components[0].Type != "agent" {
		t.Fatalf("expected type 'agent', got %q", components[0].Type)
	}
}

// ---------------------------------------------------------------------------
// Inventory: JSON serialisation
// ---------------------------------------------------------------------------

func TestInventory_JSONSerialization(t *testing.T) {
	inv := NewInventory()
	inv.Add(Component{
		Name: "test-server",
		Type: "mcp_server",
		Path: "mcp.json",
	})

	data, err := inv.JSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed Inventory
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse inventory JSON: %v", err)
	}
	if parsed.SchemaVersion != "1.0.0" {
		t.Fatalf("expected schema version 1.0.0, got %q", parsed.SchemaVersion)
	}
	if len(parsed.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(parsed.Components))
	}
}

// ---------------------------------------------------------------------------
// Inventory: WriteFile
// ---------------------------------------------------------------------------

func TestInventory_WriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ai.inventory.json")

	inv := NewInventory()
	inv.Add(Component{Name: "test", Type: "prompt", Path: "test.prompt"})

	if err := inv.WriteFile(path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}

	var parsed Inventory
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse written inventory: %v", err)
	}
	if len(parsed.Components) != 1 {
		t.Fatalf("expected 1 component in written file, got %d", len(parsed.Components))
	}
}

// ---------------------------------------------------------------------------
// ScanArtifacts integration
// ---------------------------------------------------------------------------

func TestScanArtifacts_WithAIComponents(t *testing.T) {
	dir := t.TempDir()

	mcpFile := writeFile(t, dir, "mcp.json", `{
  "mcpServers": {"github": {"command": "gh-mcp"}},
  "allowed_tools": ["*"]
}`)
	promptFile := writeFile(t, dir, "prompts/summarize.prompt", "Summarize: {user_input}")
	pyFile := writeFile(t, dir, "app.py", `model = "gpt-4"
logger.info("Prompt: " + prompt)
`)

	artifacts := []discovery.Artifact{
		{Path: "mcp.json", AbsPath: mcpFile, Type: discovery.AIComponent, Size: 100},
		{Path: "prompts/summarize.prompt", AbsPath: promptFile, Type: discovery.AIComponent, Size: 30},
		{Path: "app.py", AbsPath: pyFile, Type: discovery.Source, Size: 50},
	}

	a := NewAnalyzer()
	fs, inv, err := a.ScanArtifacts(artifacts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have findings from multiple rules.
	allFindings := fs.Findings()
	if len(allFindings) == 0 {
		t.Fatal("expected at least 1 finding from AI scan")
	}

	// Inventory should have MCP server + prompt.
	if len(inv.Components) < 2 {
		t.Fatalf("expected at least 2 inventory components, got %d", len(inv.Components))
	}
}

func TestScanArtifacts_UnreadableFile(t *testing.T) {
	artifacts := []discovery.Artifact{
		{Path: "nonexistent.py", AbsPath: "/nonexistent/path/file.py", Type: discovery.Source, Size: 0},
	}

	a := NewAnalyzer()
	_, _, err := a.ScanArtifacts(artifacts)
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

// ---------------------------------------------------------------------------
// classifyByPath
// ---------------------------------------------------------------------------

func TestClassifyByPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"agents/reviewer.yaml", "agent"},
		{"prompts/summarize.txt", "prompt"},
		{"config/settings.yaml", "ai_component"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := classifyByPath(tt.path)
			if result != tt.expected {
				t.Fatalf("expected %q for path %q, got %q", tt.expected, tt.path, result)
			}
		})
	}
}
