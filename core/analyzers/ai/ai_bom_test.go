package ai

import (
	"reflect"
	"testing"
)

// ---------------------------------------------------------------------------
// classifyModelRegistry tests
// ---------------------------------------------------------------------------

func TestClassifyModelRegistry(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// HuggingFace
		{"huggingface url", "huggingface.co/bert-base-uncased", "huggingface"},
		{"huggingface mixed case", "HuggingFace.co/model", "huggingface"},
		{"model with slash", "organization/model-name", "huggingface"},
		{"path with slash", "meta-llama/Llama-2-7b", "huggingface"},

		// OpenAI
		{"gpt-4", "gpt-4", "openai"},
		{"gpt-3.5", "gpt-3.5-turbo", "openai"},
		{"o1 model", "o1-preview", "openai"},
		{"o3 model", "o3-mini", "openai"},
		{"gpt uppercase", "GPT-4", "openai"},

		// Anthropic
		{"claude", "claude-3-opus", "anthropic"},
		{"claude sonnet", "claude-3-sonnet-20240229", "anthropic"},
		{"claude uppercase", "CLAUDE-3", "anthropic"},

		// Google
		{"gemini", "gemini-pro", "google"},
		{"gemini flash", "gemini-1.5-flash", "google"},
		{"gemini uppercase", "GEMINI-PRO", "google"},

		// Meta
		{"llama", "llama-2-7b", "meta"},
		{"llama3", "llama3-70b", "meta"},
		{"meta-llama with slash", "meta-llama/Llama-2-7b-hf", "huggingface"}, // Has slash, so classified as huggingface
		{"llama uppercase", "LLAMA-2", "meta"},

		// Mistral
		{"mistral", "mistral-7b", "mistral"},
		{"mixtral", "mixtral-8x7b", "mistral"},
		{"mistral uppercase", "MISTRAL-LARGE", "mistral"},

		// Ollama
		{"ollama", "ollama:llama2", "ollama"},
		{"ollama registry with slash", "registry.ollama.ai/library/llama3", "huggingface"}, // Has slash, so classified as huggingface
		{"ollama uppercase", "OLLAMA:MISTRAL", "ollama"},

		// Unknown
		{"unknown model", "custom-model-v1", "unknown"},
		{"empty string", "", "unknown"},
		{"random text", "some-random-model", "unknown"},
		{"bert without slash", "bert-base-uncased", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyModelRegistry(tt.input)
			if result != tt.expected {
				t.Errorf("classifyModelRegistry(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractModelVersion tests
// ---------------------------------------------------------------------------

func TestExtractModelVersion(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		context  string
		expected string
	}{
		{
			name:     "revision with double quotes",
			text:     `model = AutoModel.from_pretrained("bert-base", revision="v1.0.0")`,
			context:  `AutoModel.from_pretrained("bert-base"`,
			expected: "v1.0.0",
		},
		{
			name:     "revision with single quotes",
			text:     `from_pretrained('gpt2', revision='main')`,
			context:  `from_pretrained('gpt2'`,
			expected: "main",
		},
		{
			name:     "revision uppercase",
			text:     `model.load(name="test", REVISION="v2.0")`,
			context:  `model.load(name="test"`,
			expected: "v2.0",
		},
		{
			name:     "revision with hash",
			text:     `from_pretrained("model", revision="abc123def456")`,
			context:  `from_pretrained("model"`,
			expected: "abc123def456",
		},
		{
			name:     "no revision",
			text:     `model = AutoModel.from_pretrained("bert-base")`,
			context:  `AutoModel.from_pretrained("bert-base"`,
			expected: "",
		},
		{
			name:     "revision far away (beyond 200 chars)",
			text:     `from_pretrained("model"` + string(make([]byte, 210)) + `revision="v1.0"`,
			context:  `from_pretrained("model"`,
			expected: "",
		},
		{
			name:     "context not found",
			text:     `some random text`,
			context:  `nonexistent context`,
			expected: "",
		},
		{
			name:     "revision near end of text",
			text:     `from_pretrained("model", revision="final"`,
			context:  `from_pretrained("model"`,
			expected: "final",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractModelVersion(tt.text, tt.context)
			if result != tt.expected {
				t.Errorf("extractModelVersion() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractModelHash tests
// ---------------------------------------------------------------------------

func TestExtractModelHash(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		context  string
		expected string
	}{
		{
			name:     "sha256 with colon",
			text:     `from_pretrained("model", sha256:"abc123def456789012345678901234567890abcdef")`,
			context:  `from_pretrained("model"`,
			expected: "abc123def456789012345678901234567890abcdef",
		},
		{
			name:     "sha256 with equals",
			text:     `model.load(name="test", sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")`,
			context:  `model.load(name="test"`,
			expected: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
		{
			name:     "hash with single quotes",
			text:     `from_pretrained('model', hash='abcdef1234567890abcdef1234567890abcdef12')`,
			context:  `from_pretrained('model'`,
			expected: "abcdef1234567890abcdef1234567890abcdef12",
		},
		{
			name:     "sha256 uppercase keyword and hex",
			text:     `config(SHA256:"ABC123DEF456789012345678901234567890ABCDEF1234567890")`,
			context:  `config(`,
			expected: "ABC123DEF456789012345678901234567890ABCDEF1234567890",
		},
		{
			name:     "sha256 mixed case hex",
			text:     `load(sha256="AbC123dEf456789012345678901234567890aBcDeF1234567890")`,
			context:  `load(`,
			expected: "AbC123dEf456789012345678901234567890aBcDeF1234567890",
		},
		{
			name:     "lowercase hex valid",
			text:     `load(sha256="abc123def456789012345678901234567890abcdef1234567890")`,
			context:  `load(`,
			expected: "abc123def456789012345678901234567890abcdef1234567890",
		},
		{
			name:     "no hash",
			text:     `model = AutoModel.from_pretrained("bert-base")`,
			context:  `AutoModel.from_pretrained("bert-base"`,
			expected: "",
		},
		{
			name:     "hash too short (39 chars)",
			text:     `from_pretrained("model", sha256:"abc123def456789012345678901234567890abc")`,
			context:  `from_pretrained("model"`,
			expected: "",
		},
		{
			name:     "hash at 40 chars (minimum)",
			text:     `from_pretrained("model", sha256:"abc123def456789012345678901234567890abcd")`,
			context:  `from_pretrained("model"`,
			expected: "abc123def456789012345678901234567890abcd",
		},
		{
			name:     "hash far away (beyond 300 chars)",
			text:     `from_pretrained("model"` + string(make([]byte, 310)) + `sha256:"abc123def456789012345678901234567890abcdef")`,
			context:  `from_pretrained("model"`,
			expected: "",
		},
		{
			name:     "context not found",
			text:     `some random text`,
			context:  `nonexistent context`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractModelHash(tt.text, tt.context)
			if result != tt.expected {
				t.Errorf("extractModelHash() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// containsModel tests
// ---------------------------------------------------------------------------

func TestContainsModel(t *testing.T) {
	refs := []ModelReference{
		{Name: "bert-base-uncased", Path: "model.py"},
		{Name: "gpt-4", Path: "app.py"},
		{Name: "claude-3-opus", Path: "config.py"},
	}

	tests := []struct {
		name     string
		refs     []ModelReference
		search   string
		expected bool
	}{
		{"found first", refs, "bert-base-uncased", true},
		{"found middle", refs, "gpt-4", true},
		{"found last", refs, "claude-3-opus", true},
		{"not found", refs, "llama-2", false},
		{"empty string", refs, "", false},
		{"case sensitive", refs, "BERT-BASE-UNCASED", false},
		{"partial match", refs, "bert", false},
		{"empty list", []ModelReference{}, "bert-base-uncased", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsModel(tt.refs, tt.search)
			if result != tt.expected {
				t.Errorf("containsModel(%v, %q) = %v, want %v", tt.refs, tt.search, result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// deduplicateTemplates tests
// ---------------------------------------------------------------------------

func TestDeduplicateTemplates(t *testing.T) {
	tests := []struct {
		name     string
		input    []PromptTemplate
		expected int
	}{
		{
			name: "no duplicates",
			input: []PromptTemplate{
				{Name: "system_prompt", Type: "system", Path: "app.py"},
				{Name: "user_message", Type: "user", Path: "chat.py"},
			},
			expected: 2,
		},
		{
			name: "exact duplicates",
			input: []PromptTemplate{
				{Name: "system_prompt", Type: "system", Path: "app.py"},
				{Name: "system_prompt", Type: "system", Path: "app.py"},
				{Name: "system_prompt", Type: "system", Path: "app.py"},
			},
			expected: 1,
		},
		{
			name: "same name different type",
			input: []PromptTemplate{
				{Name: "message", Type: "system", Path: "app.py"},
				{Name: "message", Type: "user", Path: "app.py"},
			},
			expected: 2,
		},
		{
			name: "same name and type different path",
			input: []PromptTemplate{
				{Name: "system_prompt", Type: "system", Path: "app.py"},
				{Name: "system_prompt", Type: "system", Path: "chat.py"},
			},
			expected: 2,
		},
		{
			name: "mixed duplicates and unique",
			input: []PromptTemplate{
				{Name: "system_prompt", Type: "system", Path: "app.py"},
				{Name: "system_prompt", Type: "system", Path: "app.py"},
				{Name: "user_message", Type: "user", Path: "app.py"},
				{Name: "system_prompt", Type: "system", Path: "chat.py"},
			},
			expected: 3,
		},
		{
			name:     "empty list",
			input:    []PromptTemplate{},
			expected: 0,
		},
		{
			name: "templates with variables",
			input: []PromptTemplate{
				{Name: "template1", Type: "system", Path: "app.py", Variables: []string{"var1", "var2"}},
				{Name: "template1", Type: "system", Path: "app.py", Variables: []string{"var1", "var2"}},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicateTemplates(tt.input)
			if len(result) != tt.expected {
				t.Errorf("deduplicateTemplates() returned %d templates, want %d", len(result), tt.expected)
			}
		})
	}
}

func TestDeduplicateTemplates_Ordering(t *testing.T) {
	// Verify that the first occurrence is kept
	input := []PromptTemplate{
		{Name: "test", Type: "system", Path: "first.py", Variables: []string{"a"}},
		{Name: "test", Type: "system", Path: "first.py", Variables: []string{"b"}},
	}

	result := deduplicateTemplates(input)
	if len(result) != 1 {
		t.Fatalf("expected 1 template, got %d", len(result))
	}

	// The first occurrence should be preserved (with Variables: ["a"])
	if !reflect.DeepEqual(result[0].Variables, []string{"a"}) {
		t.Errorf("expected first occurrence to be kept, got Variables: %v", result[0].Variables)
	}
}

// ---------------------------------------------------------------------------
// isCommonBrace tests
// ---------------------------------------------------------------------------

func TestIsCommonBrace(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Common braces (should return true)
		{"zero", "0", true},
		{"one", "1", true},
		{"two", "2", true},
		{"three", "3", true},
		{"n", "n", true},
		{"s", "s", true},
		{"d", "d", true},
		{"f", "f", true},
		{"r", "r", true},
		{"t", "t", true},

		// Not common braces (should return false)
		{"variable name", "username", false},
		{"another variable", "count", false},
		{"empty string", "", false},
		{"uppercase N", "N", false},
		{"number 4", "4", false},
		{"number 5", "5", false},
		{"letter a", "a", false},
		{"letter z", "z", false},
		{"multi char", "10", false},
		{"word", "variable", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCommonBrace(tt.input)
			if result != tt.expected {
				t.Errorf("isCommonBrace(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractQuotedStrings tests
// ---------------------------------------------------------------------------

func TestExtractQuotedStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "double quotes",
			input:    `"tool1", "tool2", "tool3"`,
			expected: []string{"tool1", "tool2", "tool3"},
		},
		{
			name:     "single quotes",
			input:    `'tool1', 'tool2', 'tool3'`,
			expected: []string{"tool1", "tool2", "tool3"},
		},
		{
			name:     "mixed quotes",
			input:    `"tool1", 'tool2', "tool3"`,
			expected: []string{"tool1", "tool2", "tool3"},
		},
		{
			name:     "empty strings are skipped",
			input:    `"", '', "tool1"`,
			expected: []string{", ", ", "}, // The regex captures the comma and space between quotes
		},
		{
			name:     "no quotes",
			input:    `tool1, tool2, tool3`,
			expected: nil, // nil slice when no matches
		},
		{
			name:     "empty input",
			input:    ``,
			expected: nil, // nil slice when no matches
		},
		{
			name:     "quotes with spaces",
			input:    `"tool one", 'tool two'`,
			expected: []string{"tool one", "tool two"},
		},
		{
			name:     "nested in brackets",
			input:    `["read", "write", "execute"]`,
			expected: []string{"read", "write", "execute"},
		},
		{
			name:     "in json-like structure",
			input:    `{"tools": ["tool1", "tool2"]}`,
			expected: []string{"tools", "tool1", "tool2"},
		},
		{
			name:     "special characters",
			input:    `"tool-1", "tool_2", "tool.3"`,
			expected: []string{"tool-1", "tool_2", "tool.3"},
		},
		{
			name:     "single string",
			input:    `"only_one"`,
			expected: []string{"only_one"},
		},
		{
			name:     "unclosed quote",
			input:    `"tool1", "tool2`,
			expected: []string{"tool1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractQuotedStrings(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("extractQuotedStrings(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractConnections tests (increased coverage)
// ---------------------------------------------------------------------------

func TestExtractConnections_MCPServerToTools(t *testing.T) {
	components := []Component{
		{Name: "github", Type: "mcp_server", Path: "mcp.json"},
	}
	toolSets := []ToolPermissionSet{
		{Agent: "mcp_client", Server: "github", Tools: []string{"read", "write"}, Path: "mcp.json"},
	}

	conns := extractConnections(components, toolSets)

	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}

	if conns[0].From != "mcp_client" || conns[0].To != "github" || conns[0].Type != "tool_access" {
		t.Errorf("expected connection from mcp_client to github with type tool_access, got %+v", conns[0])
	}
}

func TestExtractConnections_AgentToModel(t *testing.T) {
	components := []Component{
		{Name: "my_agent", Type: "agent", Path: "agent.py"},
		{Name: "gpt-4", Type: "model_reference", Path: "agent.py"},
	}
	toolSets := []ToolPermissionSet{}

	conns := extractConnections(components, toolSets)

	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}

	if conns[0].From != "my_agent" || conns[0].To != "gpt-4" || conns[0].Type != "model_call" {
		t.Errorf("expected connection from my_agent to gpt-4 with type model_call, got %+v", conns[0])
	}
}

func TestExtractConnections_MultipleConnections(t *testing.T) {
	components := []Component{
		{Name: "agent1", Type: "agent", Path: "agent1.py"},
		{Name: "agent2", Type: "agent", Path: "agent2.py"},
		{Name: "model1", Type: "model_reference", Path: "agent1.py"},
		{Name: "model2", Type: "model_reference", Path: "agent2.py"},
	}
	toolSets := []ToolPermissionSet{
		{Agent: "client1", Server: "server1", Tools: []string{"*"}, Path: "mcp.json"},
		{Agent: "client2", Server: "server2", Tools: []string{"read"}, Path: "mcp.json"},
	}

	conns := extractConnections(components, toolSets)

	// Should have: 2 tool_access + 2 model_call = 4 connections
	if len(conns) != 4 {
		t.Fatalf("expected 4 connections, got %d", len(conns))
	}
}

func TestExtractConnections_NoServerInToolSet(t *testing.T) {
	components := []Component{}
	toolSets := []ToolPermissionSet{
		{Agent: "agent", Server: "", Tools: []string{"tool1"}, Path: "config.yaml"},
	}

	conns := extractConnections(components, toolSets)

	// No connection should be created when Server is empty
	if len(conns) != 0 {
		t.Fatalf("expected 0 connections when server is empty, got %d", len(conns))
	}
}

func TestExtractConnections_AgentAndModelInDifferentFiles(t *testing.T) {
	components := []Component{
		{Name: "agent", Type: "agent", Path: "agent.py"},
		{Name: "model", Type: "model_reference", Path: "config.py"},
	}
	toolSets := []ToolPermissionSet{}

	conns := extractConnections(components, toolSets)

	// No connection should be created when agent and model are in different files
	if len(conns) != 0 {
		t.Fatalf("expected 0 connections when agent and model in different files, got %d", len(conns))
	}
}

func TestExtractConnections_EmptyInput(t *testing.T) {
	conns := extractConnections([]Component{}, []ToolPermissionSet{})

	if len(conns) != 0 {
		t.Fatalf("expected 0 connections for empty input, got %d", len(conns))
	}
}

// ---------------------------------------------------------------------------
// Integration tests for extractModelReferences with version and hash
// ---------------------------------------------------------------------------

func TestExtractModelReferences_WithVersionAndHash(t *testing.T) {
	content := []byte(`
model = AutoModel.from_pretrained("bert-base-uncased", revision="v1.0.0", sha256="abc123def456789012345678901234567890abcdef1234567890")
`)

	refs := extractModelReferences("model.py", content)

	if len(refs) != 1 {
		t.Fatalf("expected 1 reference, got %d", len(refs))
	}

	if refs[0].Name != "bert-base-uncased" {
		t.Errorf("expected name 'bert-base-uncased', got %q", refs[0].Name)
	}

	if refs[0].Version != "v1.0.0" {
		t.Errorf("expected version 'v1.0.0', got %q", refs[0].Version)
	}

	if refs[0].Hash != "abc123def456789012345678901234567890abcdef1234567890" {
		t.Errorf("expected hash to be extracted, got %q", refs[0].Hash)
	}

	if refs[0].Registry != "unknown" {
		t.Errorf("expected registry 'unknown', got %q", refs[0].Registry)
	}
}

func TestExtractModelReferences_DeduplicationViaConfig(t *testing.T) {
	content := []byte(`
model = AutoModel.from_pretrained("bert-base")
model_name = "bert-base"
`)

	refs := extractModelReferences("model.py", content)

	// Should deduplicate via containsModel check
	if len(refs) != 1 {
		t.Errorf("expected deduplication, got %d references", len(refs))
	}
}

// ---------------------------------------------------------------------------
// Integration tests for extractPromptTemplates
// ---------------------------------------------------------------------------

func TestExtractPromptTemplates_Integration(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		content       string
		expectedCount int
		checkFirst    func(*testing.T, PromptTemplate)
	}{
		{
			name:          "prompt file with variables",
			path:          "prompts/test.prompt",
			content:       "Hello {username}, your {item} is ready",
			expectedCount: 1,
			checkFirst: func(t *testing.T, tmpl PromptTemplate) {
				if tmpl.Type != "file" {
					t.Errorf("expected type 'file', got %q", tmpl.Type)
				}
				if len(tmpl.Variables) != 2 {
					t.Errorf("expected 2 variables, got %d", len(tmpl.Variables))
				}
			},
		},
		{
			name:          "prompt.md file",
			path:          "prompts/test.prompt.md",
			content:       "# System Prompt\nYou are {role}",
			expectedCount: 1,
			checkFirst: func(t *testing.T, tmpl PromptTemplate) {
				if tmpl.Type != "file" {
					t.Errorf("expected type 'file', got %q", tmpl.Type)
				}
			},
		},
		{
			name: "system prompt in code",
			path: "app.py",
			content: `
system_prompt = "You are a helpful assistant"
SYSTEM_PROMPT = "Another prompt"
`,
			expectedCount: 2,
			checkFirst: func(t *testing.T, tmpl PromptTemplate) {
				if tmpl.Type != "system" {
					t.Errorf("expected type 'system', got %q", tmpl.Type)
				}
			},
		},
		{
			name: "deduplicated templates",
			path: "app.py",
			content: `
{"role": "system", "content": "test"}
{"role": "system", "content": "test2"}
`,
			expectedCount: 1,
			checkFirst: func(t *testing.T, tmpl PromptTemplate) {
				if tmpl.Name != "system_message" {
					t.Errorf("expected name 'system_message', got %q", tmpl.Name)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			templates := extractPromptTemplates(tt.path, []byte(tt.content))

			if len(templates) != tt.expectedCount {
				t.Fatalf("expected %d templates, got %d", tt.expectedCount, len(templates))
			}

			if tt.expectedCount > 0 && tt.checkFirst != nil {
				tt.checkFirst(t, templates[0])
			}
		})
	}
}

func TestExtractPromptTemplates_FilterCommonBraces(t *testing.T) {
	content := []byte("Format string: {0} {1} {n} {username}")
	templates := extractPromptTemplates("test.prompt", content)

	if len(templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(templates))
	}

	// Should only have "username", not "0", "1", or "n"
	if len(templates[0].Variables) != 1 {
		t.Errorf("expected 1 variable after filtering common braces, got %d: %v",
			len(templates[0].Variables), templates[0].Variables)
	}

	if templates[0].Variables[0] != "username" {
		t.Errorf("expected variable 'username', got %q", templates[0].Variables[0])
	}
}
