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
	for i := range results {
		if results[i].RuleID == ruleID {
			return &results[i]
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
	if parsed.SchemaVersion != "2.0.0" {
		t.Fatalf("expected schema version 2.0.0, got %q", parsed.SchemaVersion)
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

// ---------------------------------------------------------------------------
// AI-009: Unsafe LLM output execution
// ---------------------------------------------------------------------------

func TestDetect_UnsafeOutputExecution(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"eval python", `result = eval(response.text)`},
		{"exec python", `exec(completion)`},
		{"eval generated", `eval(generated)`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAnalyzer()
			results, err := a.ScanFile("app.py", []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			f := findingWithRule(results, "AI-009")
			if f == nil {
				t.Fatalf("expected AI-009 finding for %q", tt.name)
			}
			if f.Severity != findings.SeverityCritical {
				t.Fatalf("expected severity critical, got %s", f.Severity)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AI-010: Indirect prompt injection
// ---------------------------------------------------------------------------

func TestDetect_IndirectPromptInjection(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`fetched_content = get_url(url) + prompt`)

	results, err := a.ScanFile("rag.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-010")
	if f == nil {
		t.Fatal("expected AI-010 finding for indirect prompt injection")
	}
}

// ---------------------------------------------------------------------------
// AI-011: Agent unrestricted capability access
// ---------------------------------------------------------------------------

func TestDetect_AgentUnrestrictedAccess(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`capabilities = ["*"]`)

	results, err := a.ScanFile("agent.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-011")
	if f == nil {
		t.Fatal("expected AI-011 finding for unrestricted agent access")
	}
}

// ---------------------------------------------------------------------------
// AI-012: LLM output in SQL query
// ---------------------------------------------------------------------------

func TestDetect_LLMOutputInSQL(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`cursor.execute("SELECT * FROM " + completion)`)

	results, err := a.ScanFile("db.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-012")
	if f == nil {
		t.Fatal("expected AI-012 finding for LLM output in SQL")
	}
}

// ---------------------------------------------------------------------------
// AI-013: Error details leaked
// ---------------------------------------------------------------------------

func TestDetect_ErrorDetailsLeaked(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`traceback.format_exc() + response`)

	results, err := a.ScanFile("handler.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-013")
	if f == nil {
		t.Fatal("expected AI-013 finding for error details leaked")
	}
}

// ---------------------------------------------------------------------------
// AI-014: Model from HTTP
// ---------------------------------------------------------------------------

func TestDetect_ModelFromHTTP(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`model = AutoModel.from_pretrained("http://example.com/model")`)

	results, err := a.ScanFile("model.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-014")
	if f == nil {
		t.Fatal("expected AI-014 finding for model from HTTP")
	}
}

// ---------------------------------------------------------------------------
// AI-015: LLM output as raw HTML
// ---------------------------------------------------------------------------

func TestDetect_LLMOutputAsHTML(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"innerHTML", `element.innerHTML = response.text`},
		{"dangerouslySetInnerHTML", `<div dangerouslySetInnerHTML={{__html: completion}} />`},
		{"v-html", `<div v-html="ai_result"></div>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAnalyzer()
			results, err := a.ScanFile("component.jsx", []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			f := findingWithRule(results, "AI-015")
			if f == nil {
				t.Fatalf("expected AI-015 finding for %q", tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AI-016: System prompt exposed
// ---------------------------------------------------------------------------

func TestDetect_SystemPromptExposed(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`system_prompt = config; return response.json(system_prompt)`)

	results, err := a.ScanFile("api.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-016")
	if f == nil {
		t.Fatal("expected AI-016 finding for system prompt exposure")
	}
}

// ---------------------------------------------------------------------------
// AI-017: Excessive token limit
// ---------------------------------------------------------------------------

func TestDetect_ExcessiveTokenLimit(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"negative one", `max_tokens = -1`},
		{"very large", `max_tokens = 1000000`},
		{"maxTokens large", `maxTokens: 999999`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAnalyzer()
			results, err := a.ScanFile("config.py", []byte(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			f := findingWithRule(results, "AI-017")
			if f == nil {
				t.Fatalf("expected AI-017 finding for %q", tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AI-018: LLM output in file path
// ---------------------------------------------------------------------------

func TestDetect_LLMOutputInFilePath(t *testing.T) {
	a := NewAnalyzer()
	content := []byte(`path = os.path.join("/data", llm_output)`)

	results, err := a.ScanFile("files.py", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := findingWithRule(results, "AI-018")
	if f == nil {
		t.Fatal("expected AI-018 finding for LLM output in file path")
	}
}

// ---------------------------------------------------------------------------
// Rule count and compilation
// ---------------------------------------------------------------------------

func TestAllAIRules_Count(t *testing.T) {
	rules := builtinAIRules()
	if got := len(rules); got != 21 {
		t.Errorf("expected 21 AI rules, got %d", got)
	}
}

func TestAllAIRules_Compile(t *testing.T) {
	for _, r := range builtinAIRules() {
		if r.Pattern == "" {
			t.Errorf("rule %s has empty pattern", r.ID)
		}
	}
}
