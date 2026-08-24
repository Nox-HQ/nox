package ai

import (
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// aiRule is a compact representation used to define built-in AI security rules
// in a table. Each entry is converted to a rules.Rule by builtinAIRules().
type aiRule struct {
	id                     string
	severity               findings.Severity
	confidence             findings.Confidence
	pattern                string
	description            string
	cwe                    string
	keywords               []string
	filePatterns           []string
	ignoreFilePatterns     []string
	excludeContextKeywords []string
	tags                   []string
	remediation            string
	references             []string
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
			remediation: "Replace string concatenation with parameterised prompt templates or structured message arrays. Validate and sanitise user input before template interpolation. Use system prompts to establish behavioural boundaries. Implement output filtering to detect and block injection attempts. Consider using a prompt template library with built-in injection guards.",
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
			// \b before the noun group avoids substring matches like
			// "availablePrompts" (a menu of names, not logged content).
			pattern:     `(?i)(log|logger|logging|print|console\.log|fmt\.Print)\S*\(.*?\b(prompt|system_message|completion|response\.text|response\.content|chat_response)`,
			description: "Prompt or LLM response logged without redaction",
			cwe:         "CWE-532", keywords: []string{"prompt", "completion", "response.text", "response.content"},
			ignoreFilePatterns: []string{"*_test.go", "*_test.py", "*.test.ts", "*.test.js", "*.spec.ts", "*.spec.js"},
			tags:               []string{"ai", "logging", "data-exposure"},
			remediation:        "Redact or truncate prompt and response content before logging. Use structured logging with PII-safe fields. Avoid logging full LLM interactions in production.",
			references:         []string{"https://cwe.mitre.org/data/definitions/532.html"},
		},
		{
			id: "AI-007", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			// nox:ignore AI-007 -- rule definition, not a real finding
			pattern:     `(?i)(log|logger|print|console\.log|fmt\.Print)\S*\(.*?(openai_api_key|anthropic_api_key|api_key|bearer_token)`,
			description: "LLM API key or token logged or printed",
			cwe:         "CWE-532", keywords: []string{"openai_api_key", "anthropic_api_key"},
			// Suppress matches where the key is not being logged but rather described as
			// missing — e.g. log_error("OPENAI_API_KEY not set"). The pattern fires on
			// the key name inside the message string, but these are absence notifications,
			// not credential leaks.
			excludeContextKeywords: []string{"not set", "not found", "is not set", "isn't set", "not configured", "not provided"},
			tags:                   []string{"ai", "logging", "secrets"},
			remediation:            "Never log API keys or tokens. Use secret masking in your logging framework. Store credentials in environment variables and reference them by name only.",
			references:             []string{"https://cwe.mitre.org/data/definitions/532.html"},
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
			// \b before the verb avoids matching safe parsers like Python's
			// ast.literal_eval (the "_eval" has no word boundary).
			pattern:     `(?i)\b(?:eval|exec)\s*\(.*?(?:response|completion|output|generated|llm_output|model_output)`,
			description: "LLM output passed to code execution function",
			cwe:         "CWE-94", keywords: []string{"eval(", "exec("},
			tags: []string{"ai", "output-handling", "code-execution"},
			// nox:ignore AI-009 -- rule definition, not a real finding
			remediation: "Never pass LLM output directly to eval(), exec(), or similar code execution functions. Validate and sanitise all generated content before any form of interpretation.",
			references:  []string{"https://cwe.mitre.org/data/definitions/94.html", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			id: "AI-012", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			// Match a `.execute(` / `.query(` / `.raw(` call whose
			// argument list references an LLM-output identifier.
			//
			// Tightened from the previous `(?i)(\.execute|\.query|\.raw)\s*\(.*?(response|…)`:
			//
			//   - the method name is matched case-insensitively (Python
			//     uses lowercase, Go uses upper, JS varies), but
			//   - the LLM-output identifier is now case-sensitive
			//     lowercase only. That single change eliminates the
			//     dominant false-positive class — Go type identifiers
			//     like `*http.Response` or `LLMResponse` (UpperCamel)
			//     no longer trip the rule when they appear as return
			//     types or struct fields of a `.Execute(` call. The
			//     LLM-output identifiers in Python/JS are conventionally
			//     lowercase (`response`, `output`, `completion`).
			//   - `\b…\b` word boundaries prevent a substring match
			//     against unrelated words (e.g. "outputstream").
			//   - We deliberately keep `.*?` (not `[^)]*?`) so a true
			//     positive with nested calls in the args is still caught
			//     — e.g. `cursor.execute(safe_fn(x) + completion)`. RE2
			//     `.` doesn't cross newlines unless `(?s)` is set, so
			//     the match still bounds to the same statement.
			pattern:     `(?i:\.(execute|query|raw))\s*\(.*?(?-i:\b(response|completion|output|generated|llm_output|model_output|ai_result)\b)`,
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
			// Require an LLM-specific token; the old generic
			// output/generated/response matched ordinary file I/O (e.g. an LSP
			// binary download into a "generated" dir, PDF path building).
			pattern:     `(?i)(?:os\.path\.join|Path\(|open\(|os\.(?:remove|rename|mkdir)|shutil\.)[^)\n]*\b(?:llm_output|model_output|ai_result|ai_output|completion|generated_text|chat_response)\b`,
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
			//
			// pipeline() is intentionally not matched when it is a method name
			// suffix (e.g. has_pipeline(), conn.pipeline(), redis.pipeline()).
			// [^.a-zA-Z0-9_] before "pipeline" excludes those method-call sites
			// while still catching standalone `pipeline("task")` invocations.
			// Go RE2 has no negative lookbehind, so this character-class guard
			// is the RE2-safe equivalent.
			pattern:      `(?i)(?:from_pretrained|load_model|AutoModel|download_model|[^.a-zA-Z0-9_]pipeline)\s*\(`,
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
			// Require an LLM-specific token rather than the generic words
			// content/output/message/response, which match any console.log.
			pattern:     `(?i)(?:log|print|echo|console\.log)\s*\([^)]*\b(?:llm_response|chat_response|model_response|model_output|completion(?:_text)?|system_(?:prompt|message)|prompt_text|response\.(?:text|content)|chat_completion)\b`,
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
			// Alternation must be grouped — the previous form
			// `(seed\s*[:=]\s*None|null|undefined)` allowed bare `null` or
			// `undefined` anywhere in the file (e.g. fuzz seed corpora like
			// `f.Add([]byte(\`null\`))`). See issue #59.
			pattern:     `(?i)\bseed\s*[:=]\s*(None|null|undefined)\b`,
			description: "LLM seed not set, causing non-deterministic output",
			cwe:         "CWE-754", keywords: []string{"seed"},
			ignoreFilePatterns: []string{"*_test.go", "*_test.py", "*.test.ts", "*.test.js", "*.spec.ts", "*.spec.js"},
			tags:               []string{"ai", "reproducibility", "testing"},
			remediation:        "Set a seed value for reproducible outputs in testing and auditing. This ensures consistent behavior for the same inputs.",
			references:         []string{"https://cwe.mitre.org/data/definitions/754.html"},
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
			pattern:     `(?i)(?:response_filter|output_filter|content_filter)\s*[:=]\s*(?:None|null|false|disabled)`,
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
			// Require the gpt- prefix; the old all-optional pattern matched a
			// bare "35" anywhere (version strings, hashes, lockfiles).
			pattern:     `(?i)gpt[-_]?3[._-]?5(?:[-_]?turbo)?`,
			description: "Using deprecated GPT-3.5 model",
			cwe:         "CWE-1104", keywords: []string{"gpt-3.5", "fallback"},
			tags:        []string{"ai", "deprecation", "model-selection"},
			remediation: "Upgrade to GPT-4 or later models for production. GPT-3.5 has known limitations and will be deprecated.",
			references:  []string{"https://cwe.mitre.org/data/definitions/1104.html"},
		},
		{
			id: "AI-037", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(system|assistant)\s*[:=]\s*["'][^"']{1000}[^"']{1000,}`,
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
			// RE2 has no negative lookahead; exclude loopback hosts (localhost,
			// 127.0.0.1) by requiring the first host char(s) not begin "lo"/"12".
			pattern:     `(?i)(webhook|callback|url)\s*[:=]\s*["']http://(?:[^l1"']|l[^o"']|1[^2"'])`,
			description: "AI webhook uses insecure HTTP",
			cwe:         "CWE-295", keywords: []string{"webhook", "http://"},
			tags:        []string{"ai", "transport-security", "webhook"},
			remediation: "Use HTTPS for all webhooks. Configure TLS certificates and verify webhook signatures to prevent MITM attacks.",
			references:  []string{"https://cwe.mitre.org/data/definitions/295.html"},
		},
		{
			id: "AI-040", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)(system|prompt)\s*[:=]\s*["'][^"']*(?:sudo|rm\s+-rf|chmod\s+777|passwd)[^"']*`,
			description: "AI system prompt contains dangerous shell commands",
			cwe:         "CWE-78", keywords: []string{"system", "prompt", "sudo"},
			tags:        []string{"ai", "injection", "shell"},
			remediation: "Remove dangerous shell commands from system prompts. These can be exploited for command injection attacks.",
			references:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
		},
		{
			id: "AI-041", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(temperature|top_p)\s*[:=]\s*(?:0\.9[0-9]*|1\.0+)`,
			description: "AI model uses high temperature/top_p settings",
			cwe:         "CWE-20", keywords: []string{"temperature", "top_p"},
			tags:        []string{"ai", "reliability", "configuration"},
			remediation: "High temperature (>0.9) increases randomness and reduces consistency. Use 0.1-0.3 for deterministic outputs.",
			references:  []string{"https://cwe.mitre.org/data/definitions/20.html"},
		},
		{
			id: "AI-042", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)(api[_-]?key|token)\s*[:=]\s*["']sk-[a-zA-Z0-9]{20,}`,
			description: "Hardcoded OpenAI API key detected",
			cwe:         "CWE-798", keywords: []string{"api_key", "sk-"},
			tags:        []string{"ai", "secrets", "openai"},
			remediation: "Remove hardcoded API keys. Use environment variables or secure secret management systems.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "AI-043", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(rag|retrieval)\s*.*?\b(ssl|tls)\s*[:=]\s*(?:false|verify\s*[:=]\s*false)`,
			description: "RAG system uses insecure database connection",
			cwe:         "CWE-295", keywords: []string{"rag", "ssl", "false"},
			tags:        []string{"ai", "rag", "transport-security"},
			remediation: "Always enable TLS verification for vector database connections. Disable only for local development.",
			references:  []string{"https://cwe.mitre.org/data/definitions/295.html"},
		},
		{
			id: "AI-044", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(context|memory)\s*.*?\bwindow\s*[:=]\s*(?:\d{4,}|[1-9]\d{4,})`,
			description: "AI context window set to very high value",
			cwe:         "CWE-400", keywords: []string{"context", "window"},
			tags:        []string{"ai", "performance", "configuration"},
			remediation: "Very large context windows increase latency and cost. Use appropriate size for your use case (typically 2K-8K tokens).",
			references:  []string{"https://cwe.mitre.org/data/definitions/400.html"},
		},
		{
			id: "AI-045", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)(agent|bot)\s*.*?\b(auto|self)\s*[-_]?\b(?:improve|modify|update|patch)`,
			description: "AI agent with self-modification capability",
			cwe:         "CWE-250", keywords: []string{"agent", "auto", "modify"},
			tags:        []string{"ai", "agent", "self-modification"},
			remediation: "Disable self-modification capabilities. AI agents should not be able to modify their own code or configuration without human approval.",
			references:  []string{"https://cwe.mitre.org/data/definitions/250.html"},
		},
		{
			id: "AI-046", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(prompt|input)\s*.*?\bsanitiz(e|ation)?\s*[:=]\s*(?:false|none|disabled)`,
			description: "AI input sanitization disabled",
			cwe:         "CWE-116", keywords: []string{"prompt", "sanitize", "false"},
			tags:        []string{"ai", "input-validation", "sanitization"},
			remediation: "Enable input sanitization to prevent prompt injection and other injection attacks. Never disable in production.",
			references:  []string{"https://cwe.mitre.org/data/definitions/116.html"},
		},
		{
			id: "AI-047", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)(model|endpoint)\s*.*?\burl\s*[:=]\s*["']http://[^"']+`,
			description: "AI model endpoint uses HTTP instead of HTTPS",
			cwe:         "CWE-319", keywords: []string{"model", "url", "http://"},
			tags:        []string{"ai", "transport-security", "model-endpoint"},
			remediation: "Use HTTPS for all model API endpoints. HTTP exposes API keys and model inputs/outputs to interception.",
			references:  []string{"https://cwe.mitre.org/data/definitions/319.html"},
		},
		{
			id: "AI-048", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(cache|cached)\s*.*?\b(enabled?|ttl)\s*[:=]\s*(?:false|0|none)`,
			description: "AI response caching disabled",
			cwe:         "CWE-693", keywords: []string{"cache", "enabled", "false"},
			tags:        []string{"ai", "performance", "caching"},
			remediation: "Enable response caching for deterministic queries to reduce API costs and improve latency.",
			references:  []string{"https://cwe.mitre.org/data/definitions/693.html"},
		},
		{
			id: "AI-049", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			// \b avoids method-name matches (describeEval); AI-specific arg
			// tokens avoid DB calls like tx.exec(query).
			pattern:     `(?i)\b(?:eval|exec)\s*\([^)]*\b(?:prompt|user_input|user_content|llm_output|model_output|ai_output|ai_response|completion)\b`,
			description: "AI output passed to eval/exec function",
			cwe:         "CWE-95", keywords: []string{"eval", "exec", "prompt"},
			tags:        []string{"ai", "injection", "code-execution"},
			remediation: "Never pass AI-generated content to eval or exec. Use safe parsing methods like JSON.parse or AST parsers.",
			references:  []string{"https://cwe.mitre.org/data/definitions/95.html"},
		},
		{
			id: "AI-050", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(retry|retries)\s*[:=]\s*(?:0|false|none)`,
			description: "AI API retries disabled",
			cwe:         "CWE-705", keywords: []string{"retry", "0"},
			tags:        []string{"ai", "reliability", "error-handling"},
			remediation: "Enable retries with exponential backoff to handle transient API failures gracefully.",
			references:  []string{"https://cwe.mitre.org/data/definitions/705.html"},
		},

		// -----------------------------------------------------------------
		// OWASP LLM01: Prompt Injection — multi-language heuristic detection.
		// Confidence is medium-to-low because pure regex cannot follow
		// taint flow across function boundaries; rules trigger when a
		// known untrusted source appears within a small window of a known
		// LLM SDK invocation.
		// -----------------------------------------------------------------
		{
			id: "AI-PI-001", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:      `(?s)(?:chat\.completions\.create|ChatCompletion\.create|messages\.create|generate_content|litellm\.completion)\s*\([^)]{0,800}f["'][^"']{0,400}\{[^}]*(?:request\.(?:json|form|args|body|POST|GET)|input\s*\(|sys\.stdin|os\.environ)`,
			description:  "Prompt injection (Python): untrusted source flows into LLM call via f-string",
			cwe:          "CWE-77",
			keywords:     []string{"chat.completions.create", "messages.create", "generate_content", "litellm.completion"},
			filePatterns: []string{"*.py"},
			tags:         []string{"ai", "ai-pi", "prompt-injection", "owasp-llm01", "language:python"},
			remediation:  "Stop string-interpolating untrusted input into prompt content. Use the SDK's structured message arrays, validate the input against an allowlist, or wrap user content in explicit boundary markers and apply a system-level instruction not to follow embedded directives.",
			references:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/", "https://cwe.mitre.org/data/definitions/77.html"},
		},
		{
			id: "AI-PI-002", severity: findings.SeverityCritical, confidence: findings.ConfidenceMedium,
			pattern:      `(?s)["']\s*role\s*["']\s*:\s*["']\s*system\s*["'][^}]{0,300}["']\s*content\s*["']\s*:\s*[^,}]*(?:f["']|\.format\(|%s|\+\s*(?:request\.|user_input|user_message))`,
			description:  "Prompt injection (Python): user-tainted value flows into system-role message",
			cwe:          "CWE-77",
			keywords:     []string{"role", "system", "content"},
			filePatterns: []string{"*.py"},
			tags:         []string{"ai", "ai-pi", "prompt-injection", "owasp-llm01", "language:python"},
			remediation:  "Never put user-controlled data inside the system role. The model is trained to defer to system content; treating it as user-controlled inverts the trust boundary. Move user input to the user role and keep system content static.",
			references:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			id: "AI-PI-003", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:      "(?s)(?:openai|anthropic|client)[^\\n]{0,100}(?:chat\\.completions\\.create|messages\\.create)\\s*\\([^)]{0,800}\\$\\{[^}]*(?:req\\.(?:body|params|query|headers)|process\\.argv|new URL\\(req\\.url\\))",
			description:  "Prompt injection (JS/TS): untrusted source flows into LLM call via template literal",
			cwe:          "CWE-77",
			keywords:     []string{"chat.completions.create", "messages.create"},
			filePatterns: []string{"*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.cjs"},
			tags:         []string{"ai", "ai-pi", "prompt-injection", "owasp-llm01", "language:javascript"},
			remediation:  "Replace template-literal interpolation of req.body / req.params / req.query inside LLM message content with a structured message object. Validate inputs at the route boundary and keep system messages static.",
			references:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			id: "AI-PI-004", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:      `(?s)(?:openai|anthropic|client|llm)\.(?:CreateChatCompletion|Messages\.Create|CreateMessage)[^)]{0,800}fmt\.Sprintf\([^)]*r\.(?:FormValue|URL\.Query|Body)`,
			description:  "Prompt injection (Go): untrusted HTTP source flows into LLM call via fmt.Sprintf",
			cwe:          "CWE-77",
			keywords:     []string{"CreateChatCompletion", "Messages.Create"},
			filePatterns: []string{"*.go"},
			tags:         []string{"ai", "ai-pi", "prompt-injection", "owasp-llm01", "language:go"},
			remediation:  "Remove fmt.Sprintf-based prompt construction with HTTP request data. Use the SDK's structured message types and place untrusted content only inside user-role messages with input validation.",
			references:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			id: "AI-PI-005", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:      `(?s)(?:openai\.embeddings\.create|cohere\.embed|voyageai\.embed|google\.generativeai\.embed_content)\s*\([^)]{0,400}(?:request\.(?:json|form|body|args)|req\.body|input\s*\(|sys\.stdin)`,
			description:  "Embedding sink receives untrusted source without sanitisation",
			cwe:          "CWE-200",
			keywords:     []string{"embeddings.create", "cohere.embed", "embed_content"},
			filePatterns: []string{"*.py", "*.js", "*.ts", "*.jsx", "*.tsx"},
			tags:         []string{"ai", "ai-embed", "embedding-leak", "owasp-llm08", "owasp-llm01"},
			remediation:  "Filter and redact untrusted input before embedding. Vector DB writes are durable; PII or secrets land in retrieval results forever. Add a redaction layer on the data path, or restrict embeddings to sanitised text.",
			references:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			// Tool-call (plugin) abuse: 2023 LLM07 "Insecure Plugin Design"
			// folds into 2025 LLM06 "Excessive Agency".
			id: "AI-PI-006", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:      `(?s)["']\s*tool_calls?\s*["']\s*:\s*\[[^\]]{0,400}["']\s*arguments\s*["']\s*:\s*[^,}]*(?:f["']|\.format\(|\$\{[^}]*req\.|\+\s*request\.)`,
			description:  "Tool-call arguments contain untrusted input verbatim",
			cwe:          "CWE-77",
			keywords:     []string{"tool_calls", "arguments"},
			filePatterns: []string{"*.py", "*.js", "*.ts", "*.go"},
			tags:         []string{"ai", "ai-pi", "prompt-injection", "owasp-llm06"},
			remediation:  "Validate tool-call arguments against the schema before dispatching. Never relay untrusted input into a function-call payload without parsing.",
			references:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},

		// -----------------------------------------------------------------
		// OWASP LLM08 (2025): Vector and Embedding Weaknesses.
		// AI-EMBED-* covers vector-DB writes that consume secrets, PII, or
		// raw HTTP bodies — once embedded, the data persists in retrieval
		// results forever and travels with downstream RAG queries. In the
		// 2023 edition these were tagged LLM06 (Sensitive Information
		// Disclosure); the 2025 edition adds LLM08 specifically for
		// vector/embedding weaknesses, which is the more precise home for
		// an embedding-time leak. General (non-embedding) sensitive-info
		// disclosure would instead be LLM02.
		// -----------------------------------------------------------------
		{
			id: "AI-EMBED-001", severity: findings.SeverityCritical, confidence: findings.ConfidenceMedium,
			pattern:      `(?s)(?:embeddings\.create|cohere\.embed|voyageai\.embed|embed_content|SentenceTransformer\([^)]*\)\.encode|feature_extraction)\s*\([^)]{0,400}os\.getenv\s*\(\s*["'][A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD)`,
			description:  "Embedding sink consumes secret env var (Python)",
			cwe:          "CWE-200",
			keywords:     []string{"embeddings.create", "cohere.embed", "embed_content"},
			filePatterns: []string{"*.py"},
			tags:         []string{"ai", "ai-embed", "owasp-llm08", "language:python"},
			remediation:  "Stop embedding raw secret values into the vector store. Once embedded, the secret travels with retrieval results and is permanently exposed. Move the secret to a dedicated secret manager and embed only the data the model needs to retrieve.",
			references:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/", "https://cwe.mitre.org/data/definitions/200.html"},
		},
		{
			id: "AI-EMBED-002", severity: findings.SeverityHigh, confidence: findings.ConfidenceLow,
			pattern:      `(?s)(?:openai\.embeddings\.create|cohere\.embed|embed_content)\s*\([^)]{0,400}(?:[\w.]+@[\w.]+|\b\d{3}-\d{2}-\d{4}\b|\b(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13})\b)`,
			description:  "Embedding sink contains literal PII pattern (email/SSN/credit card)",
			cwe:          "CWE-359",
			keywords:     []string{"embeddings.create", "cohere.embed", "embed_content"},
			filePatterns: []string{"*.py", "*.js", "*.ts"},
			tags:         []string{"ai", "ai-embed", "owasp-llm08", "pii"},
			remediation:  "Redact PII before embedding. Vector DBs index on cosine similarity; PII embedded once cannot be selectively forgotten without re-indexing the entire collection.",
			references:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/", "https://cwe.mitre.org/data/definitions/359.html"},
		},
		{
			id: "AI-EMBED-003", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:      `(?s)(?:\.upsert|\.add|\.insert|pgvector)\s*\([^)]{0,400}(?:request\.(?:json|form|args|body|POST|GET)|req\.body|req\.params)`,
			description:  "Vector DB write receives raw HTTP request body without filtering",
			cwe:          "CWE-200",
			keywords:     []string{"pinecone", "qdrant", "weaviate", "chromadb", "lancedb"},
			filePatterns: []string{"*.py", "*.js", "*.ts"},
			tags:         []string{"ai", "ai-embed", "owasp-llm08", "high-bandwidth-leak"},
			remediation:  "Never embed an entire HTTP body. Extract just the fields the retrieval pipeline needs and apply a redaction layer for known-sensitive fields.",
			references:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			id: "AI-EMBED-004", severity: findings.SeverityCritical, confidence: findings.ConfidenceMedium,
			pattern:      `(?s)(?:CreateEmbeddings|client\.Embed)\s*\([^)]{0,400}os\.Getenv\s*\(\s*"[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD)`,
			description:  "Embedding sink consumes secret env var (Go)",
			cwe:          "CWE-200",
			keywords:     []string{"CreateEmbeddings", "client.Embed"},
			filePatterns: []string{"*.go"},
			tags:         []string{"ai", "ai-embed", "owasp-llm08", "language:go"},
			remediation:  "Move secret retrieval out of the embedding code path. Embed the data the retrieval pipeline needs, never the credential that protects it.",
			references:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			id: "AI-EMBED-005", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:      `(?s)(?:pinecone\.Index|chromadb\.Collection|qdrant_client\.[A-Za-z0-9_]+)\s*\([^)]*["'](?:public|demo|marketing)[\w_/-]*["']`,
			description:  "Vector store collection name suggests a public/demo namespace",
			cwe:          "CWE-200",
			keywords:     []string{"public", "demo", "marketing"},
			filePatterns: []string{"*.py", "*.js", "*.ts", "*.go"},
			tags:         []string{"ai", "ai-embed", "owasp-llm08", "audit"},
			remediation:  "Verify the destination collection's read scope. Embedding into a public/demo namespace surfaces records to anyone with retrieval access.",
			references:   []string{"https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},

		// -----------------------------------------------------------------
		// MCP server / configuration security (MCP-001..008). MCP is
		// first-class for nox positioning; these rules cover common
		// misconfigurations in mcp.json files and MCP server source code.
		// AI-004 / AI-005 also cover MCP tool exposure but predate the
		// dedicated MCP-* family. Keep both in place: AI-004/005 are the
		// generic AI-side mirror, MCP-001..008 are the operator-facing
		// MCP-specific guidance.
		// -----------------------------------------------------------------
		{
			id: "MCP-001", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)"command"\s*:\s*"(?:bash|sh|zsh|powershell|cmd\.exe|/bin/sh|/bin/bash)"`,
			description: "MCP server invokes a shell interpreter directly",
			cwe:         "CWE-78", keywords: []string{"command", "bash", "sh", "powershell"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json"},
			tags:         []string{"ai", "mcp", "tool-exposure"},
			remediation:  "Replace direct shell invocation with the specific binary the server needs. A shell-launched server inherits arbitrary subprocess capability that the MCP host can't constrain.",
			references:   []string{"https://modelcontextprotocol.io/docs/concepts/security"},
		},
		{
			id: "MCP-002", severity: findings.SeverityCritical, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)"args"\s*:\s*\[[^\]]*"(?:\$HOME|~|/Users/|/home/|C:\\\\Users\\\\)[^"]*"`,
			description: "MCP server granted broad home-directory or root-path access",
			cwe:         "CWE-732", keywords: []string{"args", "$HOME", "/Users/", "/home/"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json"},
			tags:         []string{"ai", "mcp", "filesystem-exposure"},
			remediation:  "Restrict the MCP server's path argument to the minimum project directory it needs. Granting home-directory scope means every tool call can read SSH keys, browser profiles, password managers, and shell history.",
			references:   []string{"https://modelcontextprotocol.io/docs/concepts/security"},
		},
		{
			id: "MCP-003", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)"--allow-write"|"--no-sandbox"|"--dangerously-allow-[a-z-]+"|"--unsafe"|"--insecure"`,
			description: "MCP server invoked with dangerously-permissive flags",
			cwe:         "CWE-732", keywords: []string{"allow-write", "no-sandbox", "dangerously"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json"},
			tags:         []string{"ai", "mcp", "configuration"},
			remediation:  "Remove permissive flags. If the MCP server requires elevated capability, document the operator decision in a config comment and restrict the scope to a specific subdirectory or operation.",
			references:   []string{"https://modelcontextprotocol.io/docs/concepts/security"},
		},
		{
			id: "MCP-004", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)"env"\s*:\s*\{[^}]*"[A-Z0-9_]*(?:SECRET|API_KEY|TOKEN|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*"\s*:\s*"[^$"][^"]*"`,
			description: "MCP server config embeds a secret value in the env block",
			cwe:         "CWE-798", keywords: []string{"env", "SECRET", "API_KEY", "TOKEN"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json"},
			tags:         []string{"ai", "mcp", "secrets"},
			remediation:  "Reference secrets via shell expansion ($VAR) rather than embedding the literal value. mcp.json files often live in version control or sync directories where literal secrets become exposed.",
			references:   []string{"https://modelcontextprotocol.io/docs/concepts/security"},
		},
		{
			id: "MCP-005", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?s)server\.tool\s*\(\s*"[a-zA-Z_][a-zA-Z0-9_]*"\s*\)\s*\.handler`,
			description: "MCP tool registration missing description metadata",
			cwe:         "CWE-1059", keywords: []string{"server.tool"},
			filePatterns: []string{"*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "audit"},
			remediation:  "Add a Description() call to every tool registration. The description is what the operator and the LLM see when reasoning about whether to invoke the tool. Missing descriptions are an auditability gap.",
			references:   []string{"https://modelcontextprotocol.io/docs/concepts/tools"},
		},
		{
			id: "MCP-006", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)"transport"\s*:\s*"http"|new\s+HttpServerTransport\s*\(\s*\{[^}]*"http://`,
			description: "MCP server uses plaintext HTTP transport",
			cwe:         "CWE-319", keywords: []string{"transport", "http", "HttpServerTransport"},
			filePatterns: []string{"mcp.json", "*.json", "*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "transport"},
			remediation:  "Use HTTPS for any MCP transport that crosses a network boundary. stdio transport is fine for local servers; remote MCP must be TLS-protected to prevent tool-call interception.",
			references:   []string{"https://modelcontextprotocol.io/docs/concepts/security"},
		},
		{
			id: "MCP-007", severity: findings.SeverityCritical, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)"command"\s*:\s*"(?:curl|wget|npx)\s+(?:[a-z]+://|--?[a-z]+\s+[a-z]+://)`,
			description: "MCP server fetches and executes remote code at startup",
			cwe:         "CWE-829", keywords: []string{"command", "curl", "wget", "npx"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json"},
			tags:         []string{"ai", "mcp", "supply-chain"},
			remediation:  "Pin the MCP server to a specific version installed locally. Fetching at runtime turns every host start into a supply-chain attack surface — a compromised registry can ship arbitrary code to every operator's machine.",
			references:   []string{"https://modelcontextprotocol.io/docs/concepts/security"},
		},
		{
			id: "MCP-008", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:     `(?s)server\.tool\s*\([^)]*\)[^.]*\.handler\s*\([^)]*\)\s*$`,
			description: "MCP tool handler appears unbounded (no rate limit / scope guard)",
			cwe:         "CWE-770", keywords: []string{"server.tool", "handler"},
			filePatterns: []string{"*.go", "*.ts", "*.js"},
			tags:         []string{"ai", "mcp", "abuse"},
			remediation:  "Wrap tool handlers in a rate-limited / scope-checked middleware. An LLM or compromised host can invoke handlers in tight loops; without a guard, a single bug becomes denial-of-service or quota exhaustion.",
			references:   []string{"https://modelcontextprotocol.io/docs/concepts/security"},
		},

		// -----------------------------------------------------------------
		// MCP tool poisoning (MCP-009..014). OWASP MCP03: an MCP server can
		// embed malicious instructions in the metadata the host model reads
		// — tool descriptions, input-schema field docs, and return-value
		// templates. The model treats this text as trusted context, so a
		// poisoned description can override host instructions, conceal
		// actions from the operator, or stage exfiltration. These rules scan
		// mcp.json/config files and tool-registration source. They reuse the
		// AI-PI prompt-injection heuristics but anchor them to MCP tool
		// surfaces and operator-facing remediation.
		// -----------------------------------------------------------------
		{
			id: "MCP-009", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|the\s+system)\s+(?:instructions?|prompts?|messages?|context|rules?)`,
			description: "MCP tool metadata contains an instruction-override phrase (tool poisoning)",
			cwe:         "CWE-77", keywords: []string{"ignore", "disregard", "forget", "override"},
			// The phrase MCP-009 looks for appears legitimately in the code that
			// DEFENDS against it: a guardrail's pattern list, a detector's test
			// corpus, an attack tool's payload table. There the string is what is
			// being searched for, not an instruction to a model.
			//
			// Two instances turned up in one session — a guardrail class storing
			// its injection patterns as literals (#456), and nox's own
			// core/attack/corpus.go, which took five hand-written inline waivers
			// to stop the self-scan blocking a merge. Hand-waiving each site does
			// not scale and leaves every downstream project doing the same.
			//
			// Scoped to naming words rather than anything an attacker controls:
			// a poisoned tool description is written to read as a plausible tool
			// description, so it does not call itself an injection pattern. The
			// true-positive half is pinned by
			// TestDetect_MCP009StillCatchesRealToolPoisoning — suppressing too
			// eagerly reports a clean scan of a poisoned tool, which is worse
			// than the false positive being fixed.
			excludeContextKeywords: []string{
				"injection_pattern", "injectionpattern", "injection pattern",
				"detection_pattern", "detectionpattern",
				"guardrail", "jailbreak_pattern", "known_attack",
				"payload", "corpus", "attack_pattern",
			},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json", "*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "tool-poisoning", "prompt-injection", "owasp-mcp03"},
			remediation:  "Remove the instruction-override phrasing from the tool description/schema. A tool's description is read by the host model as trusted context; text that tells the model to ignore prior instructions is a tool-poisoning payload. Pin the tool definition and review it before granting the server access.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices", "https://owasp.org/www-project-mcp-top-10/"},
		},
		{
			id: "MCP-010", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(?:do\s+not|don't|never)\s+(?:tell|inform|notify|mention|reveal|disclose|alert|show)\s+(?:this|it|anything|the\s+(?:call|result))?\s*(?:to\s+)?the\s+(?:user|human|operator|developer)`,
			description: "MCP tool metadata instructs the model to conceal actions from the user (tool poisoning)",
			cwe:         "CWE-77", keywords: []string{"do not tell", "don't tell", "do not inform", "do not reveal", "never tell"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json", "*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "tool-poisoning", "owasp-mcp03"},
			remediation:  "Delete any 'do not tell the user' directive from the tool description. Concealment instructions in tool metadata are a hallmark of tool poisoning — they coerce the host model into hiding tool behaviour from the operator.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices", "https://owasp.org/www-project-mcp-top-10/"},
		},
		{
			id: "MCP-011", severity: findings.SeverityCritical, confidence: findings.ConfidenceLow,
			// Two arms: (1) an exfiltration verb (send/upload/leak/…) targeting
			// any secret noun; (2) a passive read/cat targeting only a sensitive
			// FILE path. Bare "read secrets" is excluded — it matches legitimate
			// local secrets-config loading (temper/nomi dogfood FPs) rather than
			// exfiltration, which always pairs a read with a send or an SSH/.env path.
			pattern:     `(?i)(?:(?:exfiltrate|send|upload|leak|transmit|post|forward)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:~/\.ssh|\.ssh/|id_rsa|\.env\b|/etc/passwd|api[_-]?keys?|secrets?|credentials?|environment\s+variables?|access[_-]?tokens?)|(?:read|cat)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:~/\.ssh|\.ssh/|id_rsa|\.env\b|/etc/passwd))`,
			description: "MCP tool metadata stages credential/secret exfiltration (tool poisoning)",
			cwe:         "CWE-77", keywords: []string{"id_rsa", ".ssh", ".env", "exfiltrate", "credentials", "api key", "secrets", "access token"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json", "*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "tool-poisoning", "data-exfiltration", "owasp-mcp03"},
			remediation:  "Treat this tool as hostile until proven otherwise. A tool description that instructs the model to read SSH keys, .env files, or credentials and send them somewhere is an active exfiltration payload. Do not grant the server filesystem or network scope; pin and review the definition.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices", "https://owasp.org/www-project-mcp-top-10/"},
		},
		{
			id: "MCP-012", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]`,
			description: "MCP config or tool metadata contains hidden/zero-width or bidi control characters",
			cwe:         "CWE-77", keywords: nil,
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json"},
			tags:         []string{"ai", "mcp", "tool-poisoning", "unicode-evasion", "owasp-mcp03"},
			remediation:  "Strip zero-width and bidirectional control characters from MCP config and tool metadata. These invisible characters hide instructions from human reviewers while remaining visible to the host model — a common tool-poisoning evasion. Render the file with control characters made visible and re-review.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices", "https://owasp.org/www-project-mcp-top-10/"},
		},
		{
			id: "MCP-013", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)"(?:description|instructions?|inputSchema|schema)"\s*:\s*"[^"]*(?:<system>|<\|system\|>|system:\s|you\s+are\s+now|new\s+instructions?:|as\s+an?\s+ai\s+(?:assistant|model)|the\s+assistant\s+(?:must|should|will|shall))`,
			description: "MCP tool description injects a fake system directive at the host model",
			cwe:         "CWE-77", keywords: []string{"description", "system:", "you are now", "new instructions", "the assistant"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json", "*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "tool-poisoning", "prompt-injection", "owasp-mcp03"},
			remediation:  "A tool description must describe the tool to the operator, not issue directives to the model. Remove embedded system prompts, role reassignments, or 'the assistant must…' instructions — they hijack the host model's behaviour the moment the tool is listed.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices", "https://owasp.org/www-project-mcp-top-10/"},
		},
		{
			id: "MCP-014", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(?:after\s+(?:the\s+)?(?:first|initial|next)\s+(?:run|call|invocation|install)|once\s+(?:installed|approved|trusted|enabled)|on\s+the\s+\d+(?:st|nd|rd|th)\s+(?:call|invocation|request)|when\s+(?:no\s+one|nobody)\s+is\s+(?:watching|looking))`,
			description: "MCP tool metadata contains a conditional/time-delayed behavioural trigger",
			cwe:         "CWE-77", keywords: []string{"once installed", "once approved", "once trusted", "after the first", "when no one", "when nobody"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json", "*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "tool-poisoning", "owasp-mcp03"},
			remediation:  "Conditional triggers ('once approved…', 'after the first call…', 'when no one is watching…') in tool metadata stage delayed malicious behaviour that passes initial review. Remove the conditional language and pin the tool definition so post-approval drift is detected (see MCP-015 rug-pull detection).",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices", "https://owasp.org/www-project-mcp-top-10/"},
		},

		// -----------------------------------------------------------------
		// MCP authorization & token safety (MCP-016..021). OWASP MCP07,
		// anchored to the official MCP spec "Security Best Practices"
		// (normative MUST/SHOULD). Covers token passthrough (forbidden),
		// confused-deputy OAuth proxy, SSRF during metadata/OAuth discovery,
		// and weak session handling.
		// -----------------------------------------------------------------
		{
			id: "MCP-016", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)"?(?:pass[_-]?through|forward|relay|reuse)[_-]?(?:token|auth|authorization|credentials?|bearer)"?\s*[:=]\s*(?:true|["'](?:enabled|on|yes)["'])`,
			description: "MCP server passes incoming tokens through to downstream APIs",
			cwe:         "CWE-287", keywords: []string{"passthrough", "pass_through", "forward", "relay", "reuse", "token", "bearer", "credential"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json", "*.json", "*.yaml", "*.yml", "*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "authorization", "owasp-mcp07"},
			remediation:  "Never forward a token the MCP server received to an upstream service. The spec forbids token passthrough: a server MUST only accept tokens issued to it and MUST exchange for its own downstream credentials. Passthrough lets a stolen or over-scoped token traverse trust boundaries.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices#token-passthrough"},
		},
		{
			id: "MCP-017", severity: findings.SeverityHigh, confidence: findings.ConfidenceLow,
			pattern:     `(?i)client_id\s*[:=]\s*["'][^"']+["'][\s\S]{0,400}(?:dynamic[_-]?(?:client[_-]?)?registration|/register\b|registration_endpoint)`,
			description: "MCP OAuth proxy combines a static client ID with dynamic client registration (confused deputy)",
			cwe:         "CWE-441", keywords: []string{"client_id", "dynamic registration", "registration_endpoint", "/register"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json", "*.json", "*.yaml", "*.yml", "*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "authorization", "confused-deputy", "owasp-mcp07"},
			remediation:  "An OAuth proxy that uses a static client ID together with dynamic client registration enables a confused-deputy consent bypass. Require explicit user consent for each dynamically registered client, or issue distinct client IDs. See the spec's confused-deputy guidance.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices#confused-deputy-problem"},
		},
		{
			id: "MCP-018", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|fd00:ec2::254)`,
			description: "MCP server references a cloud metadata endpoint (SSRF target)",
			cwe:         "CWE-918", keywords: []string{"169.254.169.254", "metadata.google.internal", "metadata.azure.com", "fd00:ec2"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json", "*.json", "*.yaml", "*.yml", "*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "ssrf", "owasp-mcp07"},
			remediation:  "A reachable cloud metadata endpoint (169.254.169.254 and equivalents) is the canonical SSRF target for stealing instance credentials. Block link-local and metadata addresses in any MCP fetch/OAuth-discovery path and enforce an egress allowlist.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices", "https://owasp.org/www-project-mcp-top-10/"},
		},
		{
			id: "MCP-019", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			// Loopback (localhost/127.0.0.1) is intentionally excluded: it is
			// overwhelmingly legitimate local dev (dev webhook servers, local
			// proxies, devtools), as the roady/tokenops/scout dogfood FPs showed.
			// Private ranges and link-local remain — those are the real SSRF
			// pivots toward internal services and cloud metadata.
			pattern:     `(?i)(?:fetch|callback|redirect|webhook|discovery|oauth)[\s\S]{0,80}https?://(?:10\.\d{1,3}\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)`,
			description: "MCP fetch/OAuth-discovery target points at a private or link-local address (SSRF)",
			cwe:         "CWE-918", keywords: []string{"fetch", "callback", "redirect", "webhook", "discovery", "oauth"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json", "*.json", "*.yaml", "*.yml", "*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "ssrf", "owasp-mcp07"},
			remediation:  "MCP OAuth metadata discovery and fetch tools must reject private, loopback, and link-local targets to prevent SSRF and DNS-rebinding. Validate resolved IPs (not just hostnames) against a deny list and re-validate after redirects.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices"},
		},
		{
			id: "MCP-020", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:     `(?i)session[_-]?id\s*[:=]\s*(?:["']?\d+["']?|counter|sequence|sequential|(?:time\.Now\(\)|Date\.now\(\)|time\.time\(\)))`,
			description: "MCP session identifier is predictable (sequential or time-based)",
			cwe:         "CWE-330", keywords: []string{"session_id", "sessionid", "counter", "sequential"},
			filePatterns: []string{"*.go", "*.ts", "*.js", "*.py", "*.json", "*.yaml", "*.yml"},
			tags:         []string{"ai", "mcp", "session", "owasp-mcp07"},
			remediation:  "Generate MCP session IDs from a cryptographically secure random source. Sequential or timestamp-derived IDs are guessable, enabling session hijacking. The spec requires non-deterministic session identifiers.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices#session-hijacking"},
		},
		{
			id: "MCP-021", severity: findings.SeverityHigh, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(?:authenticat\w+|authoriz\w+|login|is[_-]?authed)[^;\n]{0,40}session[_-]?id|session[_-]?id\b[^;\n]{0,20}\bas\b[^;\n]{0,20}(?:auth|credential|identity)`,
			description: "MCP server uses the session ID as an authentication credential",
			cwe:         "CWE-287", keywords: []string{"session_id", "sessionid", "authenticate", "authorize", "login"},
			filePatterns: []string{"*.go", "*.ts", "*.js", "*.py"},
			tags:         []string{"ai", "mcp", "session", "authorization", "owasp-mcp07"},
			remediation:  "Do not use the session ID for authentication. The spec states sessions MUST NOT be used as the auth mechanism; bind each session to a verified user identity (e.g. <user_id>:<session_id>) and authenticate every request independently.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices#session-hijacking"},
		},

		// -----------------------------------------------------------------
		// MCP shadow / rogue servers (MCP-022, OWASP MCP09). Cross-server
		// name and tool shadowing (MCP-023/024) is relational across the
		// discovered config inventory and is emitted by core/mcpshadow.
		// -----------------------------------------------------------------
		{
			// Advisory (info): every remote MCP config legitimately points at a
			// URL, so this fires on normal first-party config. It is a
			// posture/inventory signal — "you trust a remote server that has no
			// cryptographic identity in the protocol" — not a defect. Surfaced
			// at info severity so it informs without failing gates or crying wolf.
			id: "MCP-022", severity: findings.SeverityInfo, confidence: findings.ConfidenceLow,
			pattern:     `(?i)"(?:url|serverurl|endpoint|baseurl)"\s*:\s*"https?://|"type"\s*:\s*"(?:sse|streamable-http|http)"`,
			description: "MCP config trusts a remote server with no protocol-level identity (advisory)",
			cwe:         "CWE-300", keywords: []string{"url", "serverUrl", "endpoint", "baseUrl", "sse", "streamable-http"},
			filePatterns: []string{"mcp.json", "claude_desktop_config.json", "*.mcp.json", "cline_mcp_settings.json", "mcp_config.json"},
			tags:         []string{"ai", "mcp", "shadow-server", "supply-chain", "owasp-mcp09"},
			remediation:  "A remote MCP server has no cryptographic identity in the protocol — a rogue or hijacked endpoint can impersonate it (shadow server). Pin the server to a verified host, prefer signed/pinned local installs, and maintain an explicit allowlist of trusted server identities rather than trusting any reachable URL.",
			references:   []string{"https://modelcontextprotocol.io/specification/draft/basic/security_best_practices", "https://owasp.org/www-project-mcp-top-10/"},
		},

		// -----------------------------------------------------------------
		// Agent-config artifacts (AGENT-001..004). The files that steer a
		// coding agent — Cursor rules, CLAUDE.md/AGENTS.md, Claude Code
		// skills, and the settings that grant tool permissions — are an
		// execution surface, not just docs: a poisoned rule file or an
		// over-broad permission grant silently changes what the agent will
		// run, read, and exfiltrate. filePatterns are scoped to the exact
		// agent-config filenames (never *.go / *.md broadly) so these never
		// fire on ordinary source or documentation.
		// -----------------------------------------------------------------
		{
			id: "AGENT-001", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			// nox:ignore AGENT-001 -- rule definition, not a real finding
			pattern:     `(?i)\b(ignore|disregard|forget|override|bypass)\b[^\n]{0,50}\b(previous|prior|earlier|above|all|system|safety|your)\b[^\n]{0,30}\b(instruction|prompt|rule|guardrail|guideline|constraint|direction|restriction)s?\b`,
			description: "Instruction-override / prompt-injection directive in an agent rules file",
			cwe:         "CWE-1427", keywords: []string{"ignore", "disregard", "forget", "override", "bypass"},
			filePatterns:       []string{".cursorrules", ".clinerules", ".windsurfrules", "*.mdc", "CLAUDE.md", "AGENTS.md", "GEMINI.md", "SKILL.md", "skill.md", "copilot-instructions.md"},
			ignoreFilePatterns: []string{"testdata/*", "*_test.go"},
			tags:               []string{"ai", "agent-config", "prompt-injection", "owasp-llm01"},
			remediation:        "An agent instruction file tells the coding agent to override its own prior/system/safety instructions — the signature of a prompt-injection or jailbreak payload embedded in a rules file. Remove the override directive. Agent rules should add constraints, never instruct the agent to discard them.",
			references:         []string{"https://cwe.mitre.org/data/definitions/1427.html", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			id: "AGENT-002", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			// nox:ignore AGENT-002 -- rule definition, not a real finding
			pattern:     `(?i)("?(dangerouslySkipPermissions|bypassPermissions|enableAllProjectMcpServers|autoApprove|skipConfirmation|disableSafeMode)"?\s*[:=]\s*true|"defaultMode"\s*:\s*"bypassPermissions"|--dangerously-skip-permissions|--yolo\b)`,
			description: "Agent settings disable the human-in-the-loop permission gate",
			cwe:         "CWE-250", keywords: []string{"dangerouslyskippermissions", "bypasspermissions", "enableallprojectmcpservers", "autoapprove", "skipconfirmation", "disablesafemode", "--dangerously-skip-permissions", "--yolo"},
			filePatterns: []string{"settings.json", "settings.local.json", "*.json", "*.toml", "*.mcp.json"},
			tags:         []string{"ai", "agent-config", "excessive-agency", "human-in-the-loop"},
			remediation:  "This setting lets the agent execute tools without human confirmation (bypass-permissions / auto-approve). Committing it to a repo makes every collaborator's agent auto-run tool calls. Remove it and keep an explicit per-tool approval policy; grant standing approval only to narrowly-scoped, read-only tools.",
			references:   []string{"https://cwe.mitre.org/data/definitions/250.html"},
		},
		{
			id: "AGENT-003", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			// nox:ignore AGENT-003 -- rule definition, not a real finding
			pattern:     `(?i)"(bash|shell|sh|zsh|execute|exec|run|write|edit|webfetch|fetch)\s*\(\s*\*\s*\)"`,
			description: "Agent permission grants a tool with an unrestricted wildcard argument",
			cwe:         "CWE-284", keywords: []string{"bash(", "shell(", "execute(", "exec(", "run(", "write(", "webfetch(", "fetch("},
			filePatterns: []string{"settings.json", "settings.local.json", "*.json", "*.mcp.json", "mcp.json"},
			tags:         []string{"ai", "agent-config", "excessive-agency", "owasp-llm06"},
			remediation:  "A permission entry like \"Bash(*)\" grants the agent an unrestricted tool (any shell command, any URL, any path). Replace the wildcard with an explicit allowlist of exact commands/paths the agent needs (e.g. \"Bash(go test:*)\"), following least privilege.",
			references:   []string{"https://cwe.mitre.org/data/definitions/284.html", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
		},
		{
			id: "AGENT-004", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			// nox:ignore AGENT-004 -- rule definition, not a real finding
			pattern:     `(?i)((do\s*not|don't|never)\s+(tell|inform|reveal|disclose|mention|notify|warn|alert)\s+(the\s+)?(user|human|operator|developer|owner)|\b(exfiltrate|leak)\b|\b(send|post|upload|forward|transmit)\b[^\n]{0,40}(https?://|webhook|api[_-]?key|secret|token|credential))`,
			description: "Data-exfiltration or concealment directive in an agent rules file",
			cwe:         "CWE-1427", keywords: []string{"do not tell", "don't tell", "never tell", "do not inform", "never reveal", "without telling", "exfiltrate", "leak", "webhook", "send", "post", "upload", "forward", "transmit"},
			filePatterns:       []string{".cursorrules", ".clinerules", ".windsurfrules", "*.mdc", "CLAUDE.md", "AGENTS.md", "GEMINI.md", "SKILL.md", "skill.md", "copilot-instructions.md"},
			ignoreFilePatterns: []string{"testdata/*", "*_test.go"},
			tags:               []string{"ai", "agent-config", "prompt-injection", "exfiltration", "owasp-llm01"},
			remediation:        "An agent rules file instructs the agent to hide actions from the user or to send data to an external sink — the signature of a data-exfiltration or rug-pull payload. Remove the directive; legitimate agent rules never tell the agent to conceal behaviour from its operator.",
			references:         []string{"https://cwe.mitre.org/data/definitions/1427.html"},
		},
		{
			id:          "AGENT-005",
			severity:    findings.SeverityHigh,
			confidence:  findings.ConfidenceMedium,
			pattern:     `(?i)"(authentication|security|securityschemes)"\s*:\s*(null|""|"none"|\[\s*\]|\{\s*\})`,
			description: "A2A agent card exposes an inter-agent endpoint with no authentication",
			cwe:         "CWE-306",
			keywords:    []string{"authentication", "securityschemes", "security"},
			// A2A agent cards are served at .well-known/agent.json (basename agent.json).
			filePatterns: []string{"agent.json", "agent-card.json", "*.agent.json"},
			tags:         []string{"ai", "agent-config", "a2a", "inter-agent"},
			remediation:  "This A2A (agent-to-agent) card declares no authentication — an empty or \"none\" security scheme — while advertising skills, so any peer can invoke the agent's tools. Define a security scheme (e.g. OAuth2 or bearer) in the agent card and enforce it on the served endpoint before exposing any skill.",
			references:   []string{"https://cwe.mitre.org/data/definitions/306.html", "https://a2a-protocol.org/"},
		},
		{
			id:         "AGENT-006",
			severity:   findings.SeverityHigh,
			confidence: findings.ConfidenceMedium,
			// Fire only when a user_config value controls the executable itself
			// ("command": "...${user_config...}") or is embedded in a shell -c
			// string — not the documented, safe case of passing it as a discrete
			// argv element (`"args": ["${user_config.path}"]`).
			pattern:      `(?i)("command"\s*:\s*"[^"]*\$\{user_config\.|"-c"\s*,\s*"[^"]*\$\{user_config\.)`,
			description:  "Desktop-extension (DXT) manifest interpolates user_config into a server command",
			cwe:          "CWE-78",
			keywords:     []string{"user_config", "command"},
			filePatterns: []string{"manifest.json", "*.dxt"},
			tags:         []string{"ai", "agent-config", "dxt", "command-injection"},
			remediation:  "A DXT desktop-extension manifest interpolates a ${user_config.*} value into the MCP server executable or a shell -c string. A malicious or mistaken config value becomes command/shell injection when the extension launches. Pass user_config values as separate, validated argv elements or environment variables; never concatenate them into the command string or a shell invocation.",
			references:   []string{"https://cwe.mitre.org/data/definitions/78.html", "https://www.anthropic.com/engineering/desktop-extensions"},
		},
	}

	out := make([]*rules.Rule, len(defs))
	for i := range defs {
		out[i] = &rules.Rule{
			ID:                     defs[i].id,
			Version:                "1.0",
			Description:            defs[i].description,
			Severity:               defs[i].severity,
			Confidence:             defs[i].confidence,
			MatcherType:            "regex",
			Pattern:                defs[i].pattern,
			FilePatterns:           defs[i].filePatterns,
			IgnoreFilePatterns:     defs[i].ignoreFilePatterns,
			ExcludeContextKeywords: defs[i].excludeContextKeywords,
			Keywords:               defs[i].keywords,
			Tags:                   defs[i].tags,
			Metadata:               map[string]string{"cwe": defs[i].cwe},
			Remediation:            defs[i].remediation,
			References:             defs[i].references,
		}
	}

	applyMCPProsePrecision(out)
	applyAINoiseGlobs(out)
	applyASIMapping(out)
	expandJSTSFilePatterns(out)
	return out
}

// expandJSTSFilePatterns broadens every rule that targets `*.ts` or `*.js` to
// also match the module and JSX variants (`*.tsx`/`*.mts`/`*.cts`,
// `*.jsx`/`*.mjs`/`*.cjs`). filepath.Match treats these as distinct globs, so a
// rule scoped to `*.ts` would silently skip a Next.js `.tsx` component — exactly
// where an AI app builds prompts and calls the model. Centralising the expansion
// keeps the per-rule filePatterns lists short and guarantees new rules inherit
// the variants. Idempotent: a rule that already lists a variant is unchanged.
func expandJSTSFilePatterns(out []*rules.Rule) {
	variants := map[string][]string{
		"*.ts": {"*.tsx", "*.mts", "*.cts"},
		"*.js": {"*.jsx", "*.mjs", "*.cjs"},
	}
	for _, r := range out {
		if len(r.FilePatterns) == 0 {
			continue // no glob → already fires on every file
		}
		have := make(map[string]bool, len(r.FilePatterns))
		for _, p := range r.FilePatterns {
			have[p] = true
		}
		for base, vs := range variants {
			if !have[base] {
				continue
			}
			for _, v := range vs {
				if !have[v] {
					r.FilePatterns = append(r.FilePatterns, v)
					have[v] = true
				}
			}
		}
	}
}

// applyASIMapping tags rules with their OWASP Top 10 for Agentic Applications
// (ASI01–ASI10, Dec 2025) category, so findings against agentic surfaces carry
// the agentic-security control the way they already carry OWASP LLM / MCP Top
// 10 tags. The tag flows into SARIF `properties.tags` for Code Scanning and
// downstream GRC. Only the categories nox has defensible static coverage for
// are mapped — memory poisoning, inter-agent comms, and cascading failures
// (ASI06/07/08) are runtime/multi-agent concerns nox doesn't statically detect,
// so they are deliberately left unmapped rather than over-claimed.
func applyASIMapping(out []*rules.Rule) {
	asi := map[string]string{
		// ASI01 Agent Goal Hijack — prompt injection / instruction manipulation.
		"AGENT-001": "owasp-asi01", "AGENT-004": "owasp-asi01",
		"AI-001": "owasp-asi01", "AI-002": "owasp-asi01", "AI-003": "owasp-asi01",
		"AI-010":    "owasp-asi01",
		"AI-PI-001": "owasp-asi01", "AI-PI-002": "owasp-asi01", "AI-PI-003": "owasp-asi01",
		"AI-PI-004": "owasp-asi01", "AI-PI-005": "owasp-asi01", "AI-PI-006": "owasp-asi01",
		// ASI02 Tool Misuse & Exploitation — unsafe / over-broad tool use.
		"AGENT-002": "owasp-asi02", "AGENT-003": "owasp-asi02", "AGENT-006": "owasp-asi02",
		"AI-004": "owasp-asi02", "AI-005": "owasp-asi02", "AI-011": "owasp-asi02",
		// ASI03 Identity & Privilege Abuse — authz, tokens, sessions, SSRF.
		"MCP-016": "owasp-asi03", "MCP-017": "owasp-asi03", "MCP-018": "owasp-asi03",
		"MCP-019": "owasp-asi03", "MCP-020": "owasp-asi03", "MCP-021": "owasp-asi03",
		// ASI04 Agentic Supply Chain — poisoned tools, servers, models.
		"AI-008": "owasp-asi04", "MCP-007": "owasp-asi04",
		"MCP-009": "owasp-asi04", "MCP-010": "owasp-asi04", "MCP-011": "owasp-asi04",
		"MCP-012": "owasp-asi04", "MCP-013": "owasp-asi04", "MCP-014": "owasp-asi04",
		"MCP-022": "owasp-asi04",
		// ASI05 Unexpected Code Execution — LLM output → code/shell execution.
		"AI-009": "owasp-asi05", "MCP-001": "owasp-asi05",
		// ASI07 Insecure Inter-Agent Communications — unauthenticated A2A.
		"AGENT-005": "owasp-asi07",
	}
	for _, r := range out {
		if tag, ok := asi[r.ID]; ok {
			r.Tags = append(r.Tags, tag)
		}
	}
}

// applyAINoiseGlobs adds test-file and documentation ignore globs to the AI
// prose / logging / model-selection rules, plus the unsafe-output-handling
// rules. Scanning the top public MCP servers showed the prose/logging rules
// firing on test fixtures, README/SKILL docs, and JSDoc; and the
// output-handling rules (AI-009/012/015/018 — eval/exec, DB query, innerHTML,
// file path from LLM output) fire on documentation that *quotes* those code
// sinks. A markdown file can't execute, so a match there is always a doc
// example, never a real vulnerability — most visibly nox's own CHANGELOG prose
// (which quotes a SQL-execute sink when documenting a past AI-012 precision
// fix) tripped AI-012 on every PR that edits the changelog. Generated/vendored
// files are handled separately by the scan.generated_paths filter.
func applyAINoiseGlobs(out []*rules.Rule) {
	noisy := map[string]bool{
		"AI-006": true, "AI-008": true, "AI-026": true, "AI-030": true,
		"AI-036": true, "AI-039": true, "AI-042": true,
		// Unsafe-output-handling rules: real code sinks, but they match prose
		// in docs that quote the sink. Skip docs/tests, keep real source.
		"AI-009": true, "AI-012": true, "AI-015": true, "AI-018": true,
	}
	globs := []string{
		"*_test.go", "*_test.py", "*.test.ts", "*.test.js", "*.spec.ts", "*.spec.js", "testdata/*",
		"*.md", "*.mdx", "*.markdown", "*.rst",
	}
	for _, r := range out {
		if noisy[r.ID] {
			r.IgnoreFilePatterns = append(r.IgnoreFilePatterns, globs...)
		}
	}
}

// applyMCPProsePrecision hardens the MCP prose rules against false positives
// (task-73). These rules scan general source and would otherwise fire on code
// comments describing an attack, defensive code, and test fixtures rather than
// on real MCP tool metadata. Dogfooding nox against 17 MCP repos surfaced this:
// e.g. MCP-018 fired on a repo's own SSRF blocklist and MCP-014 on a test
// doc-comment. We drop matches in comments, skip test files, and (for the SSRF
// rules) suppress matches that sit in a block/deny context.
func applyMCPProsePrecision(out []*rules.Rule) {
	proseFP := map[string]bool{
		"MCP-009": true, "MCP-010": true, "MCP-011": true,
		"MCP-013": true, "MCP-014": true, "MCP-018": true, "MCP-019": true,
	}
	testGlobs := []string{"*_test.go", "*_test.py", "*.test.ts", "*.test.js", "*.spec.ts", "*.spec.js", "testdata/*"}
	ssrfDenyContext := []string{"block", "deny", "denylist", "blocklist", "blocked", "disallow", "allowlist", "reject", "forbidden", "ssrf", "networkpolicy", "network policy", "egress", "cidr"}

	for _, r := range out {
		if !proseFP[r.ID] {
			continue
		}
		r.IgnoreInComments = true
		r.IgnoreFilePatterns = append(r.IgnoreFilePatterns, testGlobs...)
		if r.ID == "MCP-018" || r.ID == "MCP-019" {
			r.ExcludeContextKeywords = ssrfDenyContext
		}
	}
}
