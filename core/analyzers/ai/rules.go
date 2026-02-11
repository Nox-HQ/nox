package ai

import (
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// aiRule is a compact representation used to define built-in AI security rules
// in a table. Each entry is converted to a rules.Rule by builtinAIRules().
type aiRule struct {
	id           string
	severity     findings.Severity
	confidence   findings.Confidence
	pattern      string
	description  string
	cwe          string
	keywords     []string
	filePatterns []string
	tags         []string
	remediation  string
	references   []string
}

// builtinAIRules returns all built-in AI security rules.
func builtinAIRules() []rules.Rule {
	defs := []aiRule{
		// -----------------------------------------------------------------
		// Prompt / RAG boundary rules (AI-001 to AI-003)
		// -----------------------------------------------------------------
		{
			id: "AI-001", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(user_input|user_message|user_query)\s*[:=]\s*[^{]*\+\s*(prompt|system_prompt|instructions)`,
			description: "Prompt injection boundary marker missing or weak",
			cwe:         "CWE-77", keywords: []string{"user_input", "user_message", "user_query"},
			tags:        []string{"ai", "prompt-injection"},
			remediation: "Use structured message arrays with distinct system/user roles instead of string concatenation. Apply input sanitisation before injecting user content into prompts.",
			references:  []string{"https://cwe.mitre.org/data/definitions/77.html", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			id: "AI-002", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)(f["']|\.format\(|%s).*?(user_input|user_message|user_query|user_prompt)`,
			description: "Direct string concatenation of user input into prompt template",
			cwe:         "CWE-77", keywords: []string{"user_input", "user_message", "user_query", "user_prompt"},
			tags:        []string{"ai", "prompt-injection"},
			remediation: "Use parameterised prompt templates or structured message arrays. Never concatenate untrusted input directly into prompt strings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/77.html", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			id: "AI-003", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(context|retrieved_docs?|rag_results?|search_results?)\s*[:=].*\+\s*(prompt|system|messages)`,
			description: "RAG context injected without sanitisation boundary",
			cwe:         "CWE-77", keywords: []string{"retrieved_doc", "rag_result", "search_result"},
			tags:        []string{"ai", "rag", "prompt-injection"},
			remediation: "Wrap retrieved documents in explicit boundary markers (e.g., XML tags). Sanitise retrieved content and limit its influence on system instructions.",
			references:  []string{"https://cwe.mitre.org/data/definitions/77.html"},
		},

		// -----------------------------------------------------------------
		// Unsafe MCP / tool exposure (AI-004, AI-005)
		// -----------------------------------------------------------------
		{
			id: "AI-004", severity: findings.SeverityCritical, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)("name"\s*:\s*"(write|delete|remove|exec|execute|run|shell)")|("tool"\s*:\s*"(write|delete|remove|exec|execute|run|shell)")`,
			description: "MCP server exposes file system write tool without restrictions",
			cwe:         "CWE-284", keywords: []string{"write", "delete", "execute"},
			filePatterns: []string{"mcp.json", "*.json"},
			tags:         []string{"ai", "mcp", "tool-exposure"},
			remediation:  "Restrict MCP tools to read-only operations. Use an explicit allowlist in your mcp.json configuration and remove write/execute capabilities.",
			references:   []string{"https://cwe.mitre.org/data/definitions/284.html", "https://modelcontextprotocol.io/docs/concepts/tools"},
		},
		{
			id: "AI-005", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)"allow(ed)?_?tools"\s*:\s*\[\s*"\*"\s*\]`,
			description: "MCP configuration allows all tools without allowlist",
			cwe:         "CWE-284", keywords: []string{"allowed_tools", "allow_tools"},
			filePatterns: []string{"mcp.json", "*.json", "*.yaml", "*.yml"},
			tags:         []string{"ai", "mcp", "tool-exposure"},
			remediation:  "Replace the wildcard '*' with an explicit list of allowed tool names. Follow the principle of least privilege for agent tool access.",
			references:   []string{"https://cwe.mitre.org/data/definitions/284.html"},
		},

		// -----------------------------------------------------------------
		// Insecure logging (AI-006, AI-007)
		// -----------------------------------------------------------------
		{
			id: "AI-006", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(log|logger|logging|print|console\.log|fmt\.Print)\S*\(.*?(prompt|system_message|completion|response\.text|response\.content|chat_response)`,
			description: "Prompt or LLM response logged without redaction",
			cwe:         "CWE-532", keywords: []string{"prompt", "completion", "response.text", "response.content"},
			tags:        []string{"ai", "logging", "data-exposure"},
			remediation: "Redact or truncate prompt and response content before logging. Use structured logging with PII-safe fields. Avoid logging full LLM interactions in production.",
			references:  []string{"https://cwe.mitre.org/data/definitions/532.html"},
		},
		{
			id: "AI-007", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)(log|logger|print|console\.log|fmt\.Print)\S*\(.*?(openai_api_key|anthropic_api_key|api_key|bearer_token)`,
			description: "LLM API key or token logged or printed",
			cwe:         "CWE-532", keywords: []string{"openai_api_key", "anthropic_api_key"},
			tags:        []string{"ai", "logging", "secrets"},
			remediation: "Never log API keys or tokens. Use secret masking in your logging framework. Store credentials in environment variables and reference them by name only.",
			references:  []string{"https://cwe.mitre.org/data/definitions/532.html"},
		},

		// -----------------------------------------------------------------
		// Model supply chain (AI-008)
		// -----------------------------------------------------------------
		{
			id: "AI-008", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(model\s*[:=]\s*["'])(gpt-4|gpt-3\.5|claude|gemini|llama|mistral|command)["']`,
			description: "Model reference without version pin or hash",
			cwe:         "CWE-829", keywords: []string{"gpt-4", "gpt-3.5", "claude", "gemini", "llama", "mistral"},
			tags:        []string{"ai", "model", "supply-chain"},
			remediation: "Pin model references to specific versions (e.g., 'gpt-4-0613' instead of 'gpt-4'). This ensures reproducible behaviour and protects against unintended model changes.",
			references:  []string{"https://cwe.mitre.org/data/definitions/829.html"},
		},

		// -----------------------------------------------------------------
		// Unsafe output handling (AI-009, AI-012, AI-015, AI-018)
		// -----------------------------------------------------------------
		{
			id: "AI-009", severity: findings.SeverityCritical, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(eval|exec)\s*\(.*?(response|completion|output|generated|llm_output|model_output)`,
			description: "LLM output passed to code execution function",
			cwe:         "CWE-94", keywords: []string{"eval(", "exec("},
			tags:        []string{"ai", "output-handling", "code-execution"},
			remediation: "Never pass LLM output directly to eval(), exec(), or similar code execution functions. Validate and sanitise all generated content before any form of interpretation.",
			references:  []string{"https://cwe.mitre.org/data/definitions/94.html", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			id: "AI-012", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(\.execute|\.query|\.raw)\s*\(.*?(response|completion|output|generated|llm_output|model_output|ai_result)`,
			description: "LLM-generated text used directly in database query",
			cwe:         "CWE-89", keywords: []string{".execute(", ".query(", ".raw("},
			tags:        []string{"ai", "output-handling", "sql-injection"},
			remediation: "Never interpolate LLM output into SQL queries. Use parameterised queries or ORM methods. Validate generated SQL against an allowlist of permitted operations.",
			references:  []string{"https://cwe.mitre.org/data/definitions/89.html"},
		},
		{
			id: "AI-015", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(innerHTML|dangerouslySetInnerHTML|v-html|\.html\()\s*[=({]?\s*.*?(response|completion|output|generated|llm|ai_result|message\.content|chat_response)`,
			description: "LLM output rendered as raw HTML without escaping",
			cwe:         "CWE-79", keywords: []string{"innerhtml", "dangerouslysetinnerhtml", "v-html"},
			tags:        []string{"ai", "output-handling", "xss"},
			remediation: "Never render LLM output as raw HTML. Use text content or a sanitisation library (e.g., DOMPurify) to strip dangerous tags and attributes before rendering.",
			references:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
		},
		{
			id: "AI-018", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(os\.path\.join|Path\(|open\(|os\.(remove|rename|mkdir)|shutil\.).*?(response|completion|output|generated|llm_output|model_output|ai_result)`,
			description: "LLM output used to construct file system path",
			cwe:         "CWE-22", keywords: []string{"os.path", "shutil"},
			tags:        []string{"ai", "output-handling", "path-traversal"},
			remediation: "Never use LLM output directly in file paths. Validate against an allowlist of permitted paths, use chroot/sandbox, and reject path traversal characters (../, ~).",
			references:  []string{"https://cwe.mitre.org/data/definitions/22.html"},
		},

		// -----------------------------------------------------------------
		// Indirect prompt injection (AI-010)
		// -----------------------------------------------------------------
		{
			id: "AI-010", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(fetched_content|web_content|crawled|scraped|external_data|url_content|html_body)\s*[:=+].*?(prompt|system|messages|instructions)`,
			description: "External content concatenated into LLM prompt without sanitisation",
			cwe:         "CWE-77", keywords: []string{"fetched_content", "crawled", "scraped", "external_data"},
			tags:        []string{"ai", "prompt-injection", "indirect"},
			remediation: "Treat all externally fetched content as untrusted. Wrap it in explicit boundary markers, sanitise it, and limit its influence on system instructions.",
			references:  []string{"https://cwe.mitre.org/data/definitions/77.html"},
		},

		// -----------------------------------------------------------------
		// Excessive agency (AI-011)
		// -----------------------------------------------------------------
		{
			id: "AI-011", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(tools|capabilities|permissions|allowed_actions)\s*[:=]\s*\[?\s*["'](all|\*)["']`,
			description: "AI agent configured with unrestricted tool or capability access",
			cwe:         "CWE-269", keywords: []string{"capabilities", "allowed_actions"},
			tags:        []string{"ai", "agent", "excessive-agency"},
			remediation: "Apply the principle of least privilege. Configure agents with an explicit allowlist of specific tools and capabilities rather than wildcards.",
			references:  []string{"https://cwe.mitre.org/data/definitions/269.html"},
		},

		// -----------------------------------------------------------------
		// Information disclosure (AI-013, AI-016)
		// -----------------------------------------------------------------
		{
			id: "AI-013", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(traceback|stack_trace|stacktrace|str\(e\)|e\.message|err\.Error\(\)).*?(return|response|send|json|reply)`,
			description: "Internal error details or stack traces returned in LLM response",
			cwe:         "CWE-209", keywords: []string{"traceback", "stack_trace", "stacktrace"},
			tags:        []string{"ai", "error-handling", "information-disclosure"},
			remediation: "Return generic error messages to users. Log detailed error information server-side only. Never include stack traces, internal paths, or exception details in API responses.",
			references:  []string{"https://cwe.mitre.org/data/definitions/209.html"},
		},
		{
			id: "AI-016", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(system_prompt|system_message|system_instructions)\s*[:=].*?(return|response\.|send|expose|json\.)`,
			description: "System prompt or instructions returned to user",
			cwe:         "CWE-200", keywords: []string{"system_prompt", "system_message", "system_instructions"},
			tags:        []string{"ai", "information-disclosure", "system-prompt"},
			remediation: "Never expose system prompts to end users. System instructions should be treated as confidential configuration. Return only the model's response content.",
			references:  []string{"https://cwe.mitre.org/data/definitions/200.html"},
		},

		// -----------------------------------------------------------------
		// Supply chain (AI-014)
		// -----------------------------------------------------------------
		{
			id: "AI-014", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(from_pretrained|load_model|AutoModel|download_model|model_url|model_path)\s*[:=(].*?["']http://`,
			description: "ML model loaded from insecure HTTP source",
			cwe:         "CWE-829", keywords: []string{"from_pretrained", "load_model", "http://"},
			tags:        []string{"ai", "supply-chain", "transport-security"},
			remediation: "Always load models over HTTPS. Verify model checksums or signatures after download. Use trusted model registries with verified publishers.",
			references:  []string{"https://cwe.mitre.org/data/definitions/829.html"},
		},

		// -----------------------------------------------------------------
		// Resource management (AI-017)
		// -----------------------------------------------------------------
		{
			id: "AI-017", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(max_tokens|maxTokens|max_output_tokens)\s*[:=]\s*(-1|[1-9]\d{5,}|float\(\s*["']inf)`,
			description: "LLM API call with excessively high or unlimited token limit",
			cwe:         "CWE-770", keywords: []string{"max_tokens", "maxtokens", "max_output_tokens"},
			tags:        []string{"ai", "resource-management", "denial-of-service"},
			remediation: "Set reasonable token limits based on your use case. Implement per-user and per-request token budgets to prevent resource exhaustion and cost overruns.",
			references:  []string{"https://cwe.mitre.org/data/definitions/770.html"},
		},
	}

	out := make([]rules.Rule, len(defs))
	for i, d := range defs {
		out[i] = rules.Rule{
			ID:           d.id,
			Version:      "1.0",
			Description:  d.description,
			Severity:     d.severity,
			Confidence:   d.confidence,
			MatcherType:  "regex",
			Pattern:      d.pattern,
			FilePatterns: d.filePatterns,
			Keywords:     d.keywords,
			Tags:         d.tags,
			Metadata:     map[string]string{"cwe": d.cwe},
			Remediation:  d.remediation,
			References:   d.references,
		}
	}
	return out
}
