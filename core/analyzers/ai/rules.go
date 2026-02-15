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
func builtinAIRules() []*rules.Rule {
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
			// nox:ignore AI-002 -- rule definition, not a real finding
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
			// nox:ignore AI-006 -- rule definition, not a real finding
			pattern:     `(?i)(log|logger|logging|print|console\.log|fmt\.Print)\S*\(.*?(prompt|system_message|completion|response\.text|response\.content|chat_response)`,
			description: "Prompt or LLM response logged without redaction",
			cwe:         "CWE-532", keywords: []string{"prompt", "completion", "response.text", "response.content"},
			tags:        []string{"ai", "logging", "data-exposure"},
			remediation: "Redact or truncate prompt and response content before logging. Use structured logging with PII-safe fields. Avoid logging full LLM interactions in production.",
			references:  []string{"https://cwe.mitre.org/data/definitions/532.html"},
		},
		{
			id: "AI-007", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			// nox:ignore AI-007 -- rule definition, not a real finding
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
			// nox:ignore AI-009 -- rule definition, not a real finding
			pattern:     `(?i)(eval|exec)\s*\(.*?(response|completion|output|generated|llm_output|model_output)`,
			description: "LLM output passed to code execution function",
			cwe:         "CWE-94", keywords: []string{"eval(", "exec("},
			tags: []string{"ai", "output-handling", "code-execution"},
			// nox:ignore AI-009 -- rule definition, not a real finding
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
			// nox:ignore AI-015 -- rule definition, not a real finding
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
			// nox:ignore AI-013 -- rule definition, not a real finding
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

		// -----------------------------------------------------------------
		// Model supply chain (AI-019 to AI-021)
		// -----------------------------------------------------------------
		{
			id: "AI-019", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			// Matches model loading calls (from_pretrained, load_model, AutoModel,
			// download_model, pipeline() without a hash pin or revision= argument
			// on the same line. The negative lookahead (?!.*) is not supported in
			// Go RE2, so the pattern matches the loading call broadly; the absence
			// of a hash pin is the signal (lines with revision= or sha256 are
			// unlikely to match because the keyword filter requires the load call
			// keywords but the pattern stops before consuming the whole line).
			pattern:      `(?i)(from_pretrained|load_model|AutoModel|download_model|pipeline)\s*\(`,
			description:  "Model loaded without hash verification",
			cwe:          "CWE-494",
			keywords:     []string{"from_pretrained", "load_model", "automodel", "download_model", "pipeline"},
			filePatterns: []string{"*.py", "*.ipynb"},
			tags:         []string{"ai", "supply-chain", "integrity"},
			remediation:  "Pin model references with a hash digest (e.g., revision='sha256:...') or verify checksums after download. This prevents tampered or substituted models from being loaded silently.",
			references:   []string{"https://cwe.mitre.org/data/definitions/494.html", "https://huggingface.co/docs/hub/security"},
		},
		{
			id: "AI-020", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			// Matches HTTPS/HTTP URLs in model loading contexts that are NOT from
			// the trusted registries. Because Go RE2 does not support negative
			// lookahead, the pattern matches any URL in a model-loading call;
			// post-processing via IsUntrustedRegistry refines the result, but the
			// regex alone is sufficient for initial detection of URL-based model
			// loads from arbitrary sources.
			pattern:      `(?i)(from_pretrained|load_model|download_model|model_url|model_path|pipeline)\s*[:=(].*?["']https?://[^"'\s]+["']`,
			description:  "Model downloaded from untrusted registry",
			cwe:          "CWE-829",
			keywords:     []string{"from_pretrained", "load_model", "download_model", "model_url", "model_path", "http"},
			filePatterns: []string{"*.py", "*.ipynb", "*.yaml", "*.yml", "*.json"},
			tags:         []string{"ai", "supply-chain", "untrusted-source"},
			remediation:  "Download models only from trusted registries (Hugging Face, PyTorch Hub, TF Hub, Kaggle, Ollama). Verify publisher identity and model signatures before use.",
			references:   []string{"https://cwe.mitre.org/data/definitions/829.html"},
		},
		{
			id: "AI-021", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			// Matches references to common model file extensions (.onnx, .pt,
			// .pth, .h5, .pb, .safetensors, .gguf, .bin) in load/open calls
			// without accompanying hash or signature verification on the same line.
			pattern:      `(?i)(load|open|read|from_file)\s*\(.*?\.(onnx|pt|pth|h5|pb|safetensors|gguf|bin)["'\s)>]`,
			description:  "Model file reference without signature verification",
			cwe:          "CWE-494",
			keywords:     []string{".onnx", ".pt", ".pth", ".h5", ".pb", ".safetensors", ".gguf", ".bin"},
			filePatterns: []string{"*.py", "*.ipynb", "*.go", "*.js", "*.ts", "*.yaml", "*.yml"},
			tags:         []string{"ai", "supply-chain", "integrity"},
			remediation:  "Verify model file integrity using cryptographic hashes (SHA-256) or digital signatures before loading. Store expected digests alongside model references and validate at load time.",
			references:   []string{"https://cwe.mitre.org/data/definitions/494.html"},
		},

		// -----------------------------------------------------------------
		// More AI security rules (AI-022 to AI-040)
		// -----------------------------------------------------------------
		{
			id: "AI-022", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(temperature\s*[:=]\s*(0\.[8-9]|1\.0|1))`,
			description: "LLM temperature set too high, allowing hallucination",
			cwe:         "CWE-754", keywords: []string{"temperature"},
			tags:        []string{"ai", "reliability", "hallucination"},
			remediation: "Set temperature to 0-0.3 for factual/structured tasks. Higher values (0.7-1.0) should only be used for creative tasks with explicit user consent.",
			references:  []string{"https://cwe.mitre.org/data/definitions/754.html"},
		},
		{
			id: "AI-023", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(top_p\s*[:=]\s*0\.[0-6][0-9]?)`,
			description: "LLM top_p set too low, reducing output diversity",
			cwe:         "CWE-754", keywords: []string{"top_p"},
			tags:        []string{"ai", "reliability", "diversity"},
			remediation: "Use top_p of 0.7-0.95 for balanced output. Lower values (0.1-0.3) may cause repetitive responses and reduce response quality.",
			references:  []string{"https://cwe.mitre.org/data/definitions/754.html"},
		},
		{
			id: "AI-024", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(stop\s*[:=]\s*\[\])`,
			description: "LLM stop sequences disabled",
			cwe:         "CWE-754", keywords: []string{"stop"},
			tags:        []string{"ai", "safety", "boundaries"},
			remediation: "Configure stop sequences to prevent the model from generating unwanted content types. Never disable them completely without careful consideration.",
			references:  []string{"https://cwe.mitre.org/data/definitions/754.html"},
		},
		{
			id: "AI-025", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(api_key|api-key|apikey|secret|token)\s*[:=]\s*["'][^"']*process\.env`,
			description: "API key exposed through environment variable in code",
			cwe:         "CWE-798", keywords: []string{"api_key", "process.env"},
			tags:        []string{"ai", "secrets", "exposure"},
			remediation: "Never hardcode API keys. Use environment variables, secrets management services (AWS Secrets Manager, HashiCorp Vault), or configuration files outside version control.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "AI-026", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(log|print|echo|console\.log)\s*\(.*?(prompt|message|response|content|output)`,
			description: "LLM prompt or response logged without redaction",
			cwe:         "CWE-532", keywords: []string{"log", "prompt", "response"},
			tags:        []string{"ai", "privacy", "logging"},
			remediation: "Redact sensitive information (PII, credentials, API keys) before logging. Use structured logging with sanitization functions.",
			references:  []string{"https://cwe.mitre.org/data/definitions/532.html"},
		},
		{
			id: "AI-027", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(memory|messages|context)\s*\[.*?\]\s*\+=\s*(user_input|user_message|user_query)`,
			description: "User input directly appended to conversation memory",
			cwe:         "CWE-77", keywords: []string{"memory", "user_input"},
			tags:        []string{"ai", "prompt-injection", "memory"},
			remediation: "Sanitize and validate user input before adding to conversation history. Use message templates with role-based content separation.",
			references:  []string{"https://cwe.mitre.org/data/definitions/77.html"},
		},
		{
			id: "AI-028", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(seed\s*[:=]\s*None|null|undefined)`,
			description: "LLM seed not set, causing non-deterministic output",
			cwe:         "CWE-754", keywords: []string{"seed"},
			tags:        []string{"ai", "reproducibility", "testing"},
			remediation: "Set a seed value for reproducible outputs in testing and auditing. This ensures consistent behavior for the same inputs.",
			references:  []string{"https://cwe.mitre.org/data/definitions/754.html"},
		},
		{
			id: "AI-029", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(presence_penalty\s*[:=]\s*0| frequency_penalty\s*[:=]\s*0)`,
			description: "LLM repetition penalties disabled",
			cwe:         "CWE-754", keywords: []string{"presence_penalty", "frequency_penalty"},
			tags:        []string{"ai", "reliability", "repetition"},
			remediation: "Set presence_penalty (-2 to 0) and frequency_penalty (-2 to 0) to reduce repetitive token generation. Default values of 0 may allow excessive repetition.",
			references:  []string{"https://cwe.mitre.org/data/definitions/754.html"},
		},
		{
			id: "AI-030", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(tools?|functions?)\s*[:=]\s*\[.*?(admin|root|sudo|delete|drop|truncate)`,
			description: "AI agent has excessive tool permissions",
			cwe:         "CWE-250", keywords: []string{"tools", "admin", "delete"},
			tags:        []string{"ai", "agent", "privilege-escalation"},
			remediation: "Implement least-privilege tool access. Restrict dangerous operations (admin, delete, drop) to specific authorized workflows with human oversight.",
			references:  []string{"https://cwe.mitre.org/data/definitions/250.html"},
		},
		{
			id: "AI-031", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(tools?|functions?)\s*[:=]\s*\[.*?(exec|shell|bash|command|run)`,
			description: "AI agent has shell execution capabilities",
			cwe:         "CWE-78", keywords: []string{"tools", "exec", "shell"},
			tags:        []string{"ai", "agent", "code-execution"},
			remediation: "Avoid giving AI agents direct shell execution capabilities. Use safe wrapper functions with input validation and command allowlisting.",
			references:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
		},
		{
			id: "AI-032", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(allow_dangerous_code|enable_code_execution|run_untrusted|execute_code)\s*[:=]\s*(true|True|1|yes|Yes)`,
			description: "AI agent configured to execute untrusted code",
			cwe:         "CWE-94", keywords: []string{"allow_dangerous_code", "execute_code"},
			tags:        []string{"ai", "agent", "code-execution"},
			remediation: "Never enable code execution with untrusted inputs. Use sandboxed environments with strict resource limits if code execution is absolutely necessary.",
			references:  []string{"https://cwe.mitre.org/data/definitions/94.html"},
		},
		{
			id: "AI-033", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(response_filter|output_filter|content_filter)\s*[:=]\s*None|null|false|disabled`,
			description: "AI response content filtering disabled",
			cwe:         "CWE-754", keywords: []string{"response_filter", "content_filter"},
			tags:        []string{"ai", "safety", "content-moderation"},
			remediation: "Enable content filtering to detect and block harmful outputs. Configure filters for violence, hate speech, sexual content, and self-harm.",
			references:  []string{"https://cwe.mitre.org/data/definitions/754.html"},
		},
		{
			id: "AI-034", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(function_call|tool_choice|force_tool)\s*[:=]\s*["']?(any|auto|required)`,
			description: "AI agent forced to use tool calls without validation",
			cwe:         "CWE-754", keywords: []string{"function_call", "tool_choice"},
			tags:        []string{"ai", "agent", "tool-calling"},
			remediation: "Implement tool call validation before execution. Review tool arguments and enforce schema validation on all function parameters.",
			references:  []string{"https://cwe.mitre.org/data/definitions/754.html"},
		},
		{
			id: "AI-035", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(max_tool_calls|max_function_calls|max_iterations)\s*[:=]\s*(-1|0|null|None|undefined)`,
			description: "AI agent tool call limit disabled",
			cwe:         "CWE-770", keywords: []string{"max_tool_calls", "max_iterations"},
			tags:        []string{"ai", "agent", "resource-exhaustion"},
			remediation: "Set reasonable limits on tool calls per request (e.g., 5-10). This prevents runaway agent loops and unexpected costs.",
			references:  []string{"https://cwe.mitre.org/data/definitions/770.html"},
		},
		{
			id: "AI-036", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(fallback|gpt-)?[_-]?3[_-]?5[_-]?(turbo)?`,
			description: "Using deprecated GPT-3.5 model",
			cwe:         "CWE-1104", keywords: []string{"gpt-3.5", "fallback"},
			tags:        []string{"ai", "deprecation", "model-selection"},
			remediation: "Upgrade to GPT-4 or later models for production. GPT-3.5 has known limitations and will be deprecated.",
			references:  []string{"https://cwe.mitre.org/data/definitions/1104.html"},
		},
		{
			id: "AI-037", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(system|assistant)\s*[:=]\s*["'][^"']{2000,}`,
			description: "Excessively long system prompt may cause inconsistency",
			cwe:         "CWE-754", keywords: []string{"system", "prompt"},
			tags:        []string{"ai", "reliability", "prompt-engineering"},
			remediation: "Keep system prompts under 2000 tokens. Very long prompts can cause inconsistent model behavior and higher latency.",
			references:  []string{"https://cwe.mitre.org/data/definitions/754.html"},
		},
		{
			id: "AI-038", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(embed|embedding).*?(api[_-]?key|token|secret).*?(vector|store|index)`,
			description: "Embedding API key stored with vectors",
			cwe:         "CWE-798", keywords: []string{"embed", "api_key", "vector"},
			tags:        []string{"ai", "secrets", "storage"},
			remediation: "Never store API keys alongside embeddings or vector data. Use separate secret management for API credentials.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "AI-039", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(webhook|callback|url)\s*[:=]\s*["']http://(?!localhost|127\.0\.0\.1)`,
			description: "AI webhook uses insecure HTTP",
			cwe:         "CWE-295", keywords: []string{"webhook", "http://"},
			tags:        []string{"ai", "transport-security", "webhook"},
			remediation: "Use HTTPS for all webhooks. Configure TLS certificates and verify webhook signatures to prevent MITM attacks.",
			references:  []string{"https://cwe.mitre.org/data/definitions/295.html"},
		},
	}

	out := make([]*rules.Rule, len(defs))
	for i := range defs {
		out[i] = &rules.Rule{
			ID:           defs[i].id,
			Version:      "1.0",
			Description:  defs[i].description,
			Severity:     defs[i].severity,
			Confidence:   defs[i].confidence,
			MatcherType:  "regex",
			Pattern:      defs[i].pattern,
			FilePatterns: defs[i].filePatterns,
			Keywords:     defs[i].keywords,
			Tags:         defs[i].tags,
			Metadata:     map[string]string{"cwe": defs[i].cwe},
			Remediation:  defs[i].remediation,
			References:   defs[i].references,
		}
	}
	return out
}
