// Polyglot AI inventory recognisers. Extends the AIComponent-scoped
// extractors with cross-language SDK invocation detection so that a Go
// service calling go-openai or a Python file calling
// `client.chat.completions.create` shows up in the AIBOM regardless of
// whether the file lives under prompts/ or agents/.
//
// Detection is regex-only and intentionally conservative: a marker has to
// look like an SDK call (function-call shape with model=/model: argument).
// Bare strings of "openai" in comments don't count.

package ai

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// isSourceFile reports whether path is a code file we should consider for
// AI SDK invocation detection. Excludes vendored deps, lockfiles, generated
// code, and binary blobs implicitly via the extension whitelist.
func isSourceFile(path string) bool {
	switch {
	case strings.HasSuffix(path, ".py"):
	case strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".jsx"),
		strings.HasSuffix(path, ".ts"), strings.HasSuffix(path, ".tsx"),
		strings.HasSuffix(path, ".mjs"), strings.HasSuffix(path, ".cjs"):
	case strings.HasSuffix(path, ".go"):
	case strings.HasSuffix(path, ".rb"):
	case strings.HasSuffix(path, ".java"), strings.HasSuffix(path, ".kt"):
	case strings.HasSuffix(path, ".cs"):
	case strings.HasSuffix(path, ".rs"):
	default:
		return false
	}
	// Skip vendored / generated-looking paths.
	for _, exclude := range []string{"vendor/", "node_modules/", "dist/", "build/", ".gen.", "_test."} {
		if strings.Contains(path, exclude) {
			return false
		}
	}
	return true
}

// likelyAIMarkers is a fast bytewise allowlist. If none of these strings
// appear in the file, no AI extraction runs.
var likelyAIMarkers = [][]byte{
	[]byte("openai"),
	[]byte("anthropic"),
	[]byte("Anthropic"),
	[]byte("OpenAI"),
	[]byte("google.generativeai"),
	[]byte("@google/generative-ai"),
	[]byte("cohere"),
	[]byte("mistralai"),
	[]byte("voyageai"),
	[]byte("litellm"),
	[]byte("ollama"),
	[]byte("bedrock"),
	[]byte("AzureOpenAI"),
	[]byte("@azure/openai"),
	[]byte("langchain"),
	[]byte("llama_index"),
	[]byte("LlamaIndex"),
	[]byte("semantic-kernel"),
	[]byte("SemanticKernel"),
	[]byte("autogen"),
	[]byte("crewai"),
	[]byte("CrewAI"),
	[]byte("haystack"),
	[]byte("dspy"),
	[]byte("agent-go"),
	[]byte("praxis"),
	[]byte("pinecone"),
	[]byte("qdrant"),
	[]byte("weaviate"),
	[]byte("chromadb"),
	[]byte("lancedb"),
	[]byte("pgvector"),
	[]byte("milvus"),
	[]byte("sentence_transformers"),
	[]byte("SentenceTransformer"),
	[]byte("HuggingFace"),
	[]byte("huggingface"),
	[]byte("from_pretrained"),
	[]byte("modelcontextprotocol"),
}

// isLikelyAIContent runs a cheap substring scan against the AI marker list.
// Avoids running the regex extractors on every file in a large codebase.
func isLikelyAIContent(content []byte) bool {
	for _, m := range likelyAIMarkers {
		// strings.Contains via []byte is just bytes.Contains.
		if indexBytes(content, m) >= 0 {
			return true
		}
	}
	return false
}

// indexBytes is a tiny stand-in for bytes.Index without importing the
// bytes package at top-level (file-local helper).
func indexBytes(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// sdkInvocationPattern is one regex that captures a model identifier from
// a known SDK call site. Capture group 1 must be the model name.
type sdkInvocationPattern struct {
	provider string
	re       *regexp.Regexp
}

// providerInvocations covers the major LLM SDK call sites across Python,
// JavaScript/TypeScript, and Go. Captures the model name argument.
var providerInvocations = []sdkInvocationPattern{
	// chat.completions.create(model="gpt-...") / messages.create(model="claude-...")
	{provider: "openai", re: regexp.MustCompile(`(?:chat\.completions\.create|chat\.completions\.stream|completions\.create|ChatCompletion\.create)\s*\([^)]*model\s*[:=]\s*["']([^"']+)["']`)},
	{provider: "anthropic", re: regexp.MustCompile(`messages\.(?:create|stream)\s*\([^)]*model\s*[:=]\s*["']([^"']+)["']`)},
	{provider: "google", re: regexp.MustCompile(`(?:GenerativeModel|generateContent|generate_content)\s*\([^)]*["']([a-zA-Z0-9-]*gemini[a-zA-Z0-9.-]*)["']`)},
	{provider: "cohere", re: regexp.MustCompile(`cohere\.(?:Client\([^)]*\)\.)?(?:chat|generate|embed)\s*\([^)]*model\s*[:=]\s*["']([^"']+)["']`)},
	{provider: "mistral", re: regexp.MustCompile(`mistralai[^(]*\([^)]*model\s*[:=]\s*["']([^"']+)["']`)},
	// Bedrock — model id is `anthropic.claude-...` or `meta.llama3-...`.
	{provider: "bedrock", re: regexp.MustCompile(`invoke_model\s*\([^)]*modelId\s*[:=]\s*["']([^"']+)["']`)},
	// Local (Ollama).
	{provider: "ollama", re: regexp.MustCompile(`ollama\.(?:Client\([^)]*\)\.)?(?:Chat|Generate|chat|generate)\s*\([^)]*model\s*[:=]\s*["']([^"']+)["']`)},
	// LiteLLM router (provider-prefixed).
	{provider: "litellm", re: regexp.MustCompile(`litellm\.(?:completion|acompletion)\s*\([^)]*model\s*[:=]\s*["']([^"']+)["']`)},
	// Go — go-openai shape.
	{provider: "openai", re: regexp.MustCompile(`openai\.ChatCompletionRequest\s*\{[^}]*Model\s*:\s*(?:openai\.[A-Za-z0-9]+|"([^"]+)")`)},
	// Anthropic Go SDK.
	{provider: "anthropic", re: regexp.MustCompile(`anthropic\.MessageNewParams\s*\{[^}]*Model\s*:\s*(?:anthropic\.[A-Za-z0-9]+|"([^"]+)")`)},
}

// extractSDKInvocations returns ModelReference entries for every SDK
// invocation detected in the file. Provider classification is taken from
// the matching pattern (overrides classifyModelRegistry's prefix-based
// guess) so that an `azure.openai` deployment shows up correctly even
// when its model name is a custom string. The result is enriched with
// the invocation's line number, the auth env var (when an api_key is
// passed inline), and the endpoint / base URL (Azure, Bedrock, custom).
func extractSDKInvocations(path string, content []byte) []ModelReference {
	text := string(content)
	endpointGuess := detectEndpoint(text)
	authGuess := detectAuthEnvVar(text)

	var refs []ModelReference
	for _, p := range providerInvocations {
		locs := p.re.FindAllSubmatchIndex(content, -1)
		for _, m := range locs {
			if len(m) < 4 || m[2] == -1 {
				continue
			}
			name := string(content[m[2]:m[3]])
			if name == "" {
				continue
			}
			refs = append(refs, ModelReference{
				Name:       name,
				Registry:   p.provider,
				Path:       path,
				Line:       lexctx.LineForOffset(content, m[0]),
				AuthEnvVar: authGuess,
				Endpoint:   endpointGuess,
			})
		}
	}
	return refs
}

// detectAuthEnvVar inspects content for `api_key = os.getenv("X")` /
// `process.env.X` style references commonly used to feed LLM clients.
// Returns the env var name when one matches, or "" otherwise.
func detectAuthEnvVar(text string) string {
	// These are detector regexes, not credentials: they match
	// "API_KEY"/"TOKEN"/"SECRET"/"PASSWORD" identifiers in scanned source.
	//
	// The waivers are per-line and trailing. A directive applies to exactly one
	// line, so the single directive that used to sit above this block waived
	// nothing at all — every pattern below was reported despite looking waived.
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`os\.getenv\s*\(\s*["']([A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD))["']`), // nox:ignore SEC-161,SEC-163 -- detector pattern, not a credential
		regexp.MustCompile(`os\.environ\[\s*["']([A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD))["']`),   // nox:ignore SEC-161,SEC-163 -- detector pattern, not a credential
		regexp.MustCompile(`process\.env\.([A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD))`),
		regexp.MustCompile(`process\.env\[\s*["']([A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD))["']`), // nox:ignore SEC-161,SEC-163 -- detector pattern, not a credential
		regexp.MustCompile(`os\.Getenv\s*\(\s*"([A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD))"\s*\)`), // nox:ignore SEC-161,SEC-163 -- detector pattern, not a credential
	}
	for _, re := range patterns {
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

// detectEndpoint extracts a non-default LLM endpoint URL when present.
// Captures Azure OpenAI deployment names, AWS Bedrock regions, and
// custom base_url values.
func detectEndpoint(text string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`base_url\s*[:=]\s*["']([^"']+)["']`),
		regexp.MustCompile(`baseURL\s*:\s*["']([^"']+)["']`),
		regexp.MustCompile(`azure_endpoint\s*[:=]\s*["']([^"']+)["']`),
		regexp.MustCompile(`AzureOpenAI\s*\([^)]*endpoint\s*[:=]\s*["']([^"']+)["']`),
		regexp.MustCompile(`bedrock-runtime[^"']*['"]?,?\s*region_name\s*=\s*["']([^"']+)["']`),
	}
	for _, re := range patterns {
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

// frameworkPattern recognises agent / vector-store framework usage and
// emits a Component for the inventory. Designed to over-report — a single
// import line is enough to register the framework as present.
type frameworkPattern struct {
	componentName string
	componentType string
	pattern       *regexp.Regexp
}

var frameworkPatterns = []frameworkPattern{
	// Agent frameworks.
	{componentName: "langchain", componentType: "agent_framework", pattern: regexp.MustCompile(`(?m)(?:from\s+langchain|import\s+langchain|require\s*\(\s*['"]langchain|"langchain")`)},
	{componentName: "llamaindex", componentType: "agent_framework", pattern: regexp.MustCompile(`(?m)(?:from\s+llama_index|import\s+llama_index|llamaindex|@llamaindex/)`)},
	{componentName: "autogen", componentType: "agent_framework", pattern: regexp.MustCompile(`(?m)(?:from\s+autogen|import\s+autogen|"autogen")`)},
	{componentName: "crewai", componentType: "agent_framework", pattern: regexp.MustCompile(`(?m)(?:from\s+crewai|import\s+crewai|CrewAI)`)},
	{componentName: "semantic-kernel", componentType: "agent_framework", pattern: regexp.MustCompile(`(?m)(?:Microsoft\.SemanticKernel|semantic_kernel|@microsoft/semantic-kernel)`)},
	{componentName: "haystack", componentType: "agent_framework", pattern: regexp.MustCompile(`(?m)(?:from\s+haystack|import\s+haystack)`)},
	{componentName: "vercel-ai", componentType: "agent_framework", pattern: regexp.MustCompile(`(?m)(?:from\s+['"]ai['"]|require\s*\(\s*['"]ai['"]|import\s+\{[^}]+\}\s+from\s+['"]ai['"])`)},
	{componentName: "agent-go", componentType: "agent_framework", pattern: regexp.MustCompile(`agent-go|felixgeelhaar/agent-go`)},
	{componentName: "praxis", componentType: "agent_framework", pattern: regexp.MustCompile(`felixgeelhaar/praxis|praxis\.Capability|capability\.Registry`)},
	{componentName: "langchaingo", componentType: "agent_framework", pattern: regexp.MustCompile(`tmc/langchaingo`)},
	// Vector stores.
	{componentName: "pinecone", componentType: "vector_store", pattern: regexp.MustCompile(`(?m)(?:import\s+pinecone|from\s+pinecone|pinecone-database/pinecone|pinecone-io/go-pinecone)`)},
	{componentName: "qdrant", componentType: "vector_store", pattern: regexp.MustCompile(`(?m)(?:qdrant_client|@qdrant/js-client-rest|qdrant/go-client)`)},
	{componentName: "weaviate", componentType: "vector_store", pattern: regexp.MustCompile(`(?m)(?:weaviate-client|weaviate-ts-client|weaviate\.io)`)},
	{componentName: "chroma", componentType: "vector_store", pattern: regexp.MustCompile(`(?m)(?:import\s+chromadb|from\s+chromadb|chromadb\b)`)},
	{componentName: "lancedb", componentType: "vector_store", pattern: regexp.MustCompile(`(?m)(?:import\s+lancedb|@lancedb/)`)},
	{componentName: "pgvector", componentType: "vector_store", pattern: regexp.MustCompile(`(?m)(?:pgvector\b|pgvector-go|pgvector/pgvector)`)},
	{componentName: "milvus", componentType: "vector_store", pattern: regexp.MustCompile(`(?m)(?:pymilvus|milvus-sdk-go|@zilliz/milvus2-sdk-node)`)},
	// MCP.
	{componentName: "mcp", componentType: "mcp_runtime", pattern: regexp.MustCompile(`(?m)(?:modelcontextprotocol|mcp-go|@modelcontextprotocol/sdk)`)},
}

// extractFrameworkComponents returns one Component per framework detected
// in the file content. Each detection means "this file uses that
// framework" — coarse, but sufficient for an AIBOM inventory.
func extractFrameworkComponents(path string, content []byte) []Component {
	var out []Component
	seen := map[string]bool{}
	for _, p := range frameworkPatterns {
		if seen[p.componentName] {
			continue
		}
		if p.pattern.Match(content) {
			seen[p.componentName] = true
			out = append(out, Component{
				Name: p.componentName,
				Type: p.componentType,
				Path: path,
			})
		}
	}
	return out
}
