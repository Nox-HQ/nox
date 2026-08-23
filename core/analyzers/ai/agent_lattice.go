// Agent tool-use lattice analysis (OWASP LLM06: Excessive Agency, 2025 edition;
// the 2023 "Insecure Plugin Design" category folds into Excessive Agency).
//
// The lattice analyzer scans source files for tool-registration call sites
// across multiple agent frameworks, normalises tool names to capability
// tags, and emits findings when a single agent context exposes a dangerous
// combination (file_read + http_request, shell_exec, etc.).
//
// Detection is per file: a "context" is the union of every tool registered
// in the same source file. This intentionally over-approximates real
// agents — a file that registers tools for many separate agents will still
// trigger lattice findings, which is the conservative direction (false
// positives over false negatives).

package ai

import (
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"

	"github.com/nox-hq/nox/core/findings"
)

// CapabilityTag is a normalised label for a tool's underlying primitive.
// Tag names are deliberately coarse so that "readFile", "fs.read",
// "read_file", and "fileRead" all collapse to file_read.
type CapabilityTag string

// Capability tag constants used by the dangerous-combination policy.
const (
	CapFileRead        CapabilityTag = "file_read"
	CapFileWrite       CapabilityTag = "file_write"
	CapShellExec       CapabilityTag = "shell_exec"
	CapHTTPRequest     CapabilityTag = "http_request"
	CapEmailSend       CapabilityTag = "email_send"
	CapWebhookPost     CapabilityTag = "webhook_post"
	CapDatabaseRead    CapabilityTag = "database_read"
	CapDatabaseWrite   CapabilityTag = "database_write"
	CapGitPush         CapabilityTag = "git_push"
	CapReadSecret      CapabilityTag = "read_secret"
	CapCloudIAMModify  CapabilityTag = "cloud_iam_modify"
	CapPaymentInitiate CapabilityTag = "payment_initiate"
	CapHumanApproval   CapabilityTag = "human_approval_required"
	CapUntrustedInput  CapabilityTag = "untrusted_input_path"
)

// extractedTool is a single tool registration discovered in source.
// description is the operator-/LLM-facing string passed at registration
// time; capturing it lets AIBOM downstream consumers audit whether the
// description matches what the tool actually does. Mis-described tools
// are a real LLM06 pattern (`name="read_only"` granting write).
type extractedTool struct {
	name        string
	line        int
	description string
	tags        []CapabilityTag
}

// toolPattern is one regex per agent framework that captures a tool name.
// The first capture group must be the tool name.
type toolPattern struct {
	framework string
	re        *regexp.Regexp
}

var (
	// Python frameworks.
	pyPatterns = []toolPattern{
		// LangChain @tool decorator and Tool(name="...") factory.
		{framework: "langchain", re: regexp.MustCompile(`(?m)^\s*@tool\s*\(\s*["']([a-zA-Z0-9_]+)["']`)},
		{framework: "langchain", re: regexp.MustCompile(`Tool\s*\(\s*name\s*=\s*["']([a-zA-Z0-9_]+)["']`)},
		{framework: "langchain", re: regexp.MustCompile(`StructuredTool\.from_function\s*\([^)]*name\s*=\s*["']([a-zA-Z0-9_]+)["']`)},
		// LlamaIndex.
		{framework: "llamaindex", re: regexp.MustCompile(`FunctionTool\.from_defaults\s*\([^)]*name\s*=\s*["']([a-zA-Z0-9_]+)["']`)},
		// AutoGen.
		{framework: "autogen", re: regexp.MustCompile(`register_function\s*\(\s*[a-zA-Z_]+\s*,\s*name\s*=\s*["']([a-zA-Z0-9_]+)["']`)},
		// MCP server (Python SDK).
		{framework: "mcp", re: regexp.MustCompile(`@server\.list_tools\(\)|add_tool\s*\(\s*Tool\s*\(\s*name\s*=\s*["']([a-zA-Z0-9_]+)["']`)},
		// OpenAI / Anthropic direct tools= entries with name.
		{framework: "openai", re: regexp.MustCompile(`["']function["']\s*:\s*\{[^}]*["']name["']\s*:\s*["']([a-zA-Z0-9_]+)["']`)},
	}

	// JavaScript / TypeScript frameworks.
	jsPatterns = []toolPattern{
		// LangChain.js DynamicTool.
		{framework: "langchain.js", re: regexp.MustCompile(`new\s+DynamicTool\s*\(\s*\{[^}]*name\s*:\s*["']([a-zA-Z0-9_]+)["']`)},
		{framework: "langchain.js", re: regexp.MustCompile(`tool\s*\(\s*\{[^}]*name\s*:\s*["']([a-zA-Z0-9_]+)["']`)},
		// Vercel AI SDK tool({ ... }).
		{framework: "ai-sdk", re: regexp.MustCompile(`tool\s*\(\s*\{\s*description[^}]*\}\s*\)\s*$`)},
		// Direct OpenAI/Anthropic tools array.
		{framework: "openai", re: regexp.MustCompile(`["']?function["']?\s*:\s*\{[^}]*["']?name["']?\s*:\s*["']([a-zA-Z0-9_]+)["']`)},
		// MCP TS SDK.
		{framework: "mcp-ts", re: regexp.MustCompile(`server\.tool\s*\(\s*["']([a-zA-Z0-9_]+)["']`)},
	}

	// Go frameworks.
	goPatterns = []toolPattern{
		// Praxis capability registry.
		{framework: "praxis", re: regexp.MustCompile(`Registry\.Register\s*\(\s*["']([a-zA-Z0-9_]+)["']`)},
		{framework: "praxis", re: regexp.MustCompile(`capability\.Capability\s*\{\s*Name\s*:\s*["']([a-zA-Z0-9_]+)["']`)},
		// agent-go.
		{framework: "agent-go", re: regexp.MustCompile(`\.AddTool\s*\(\s*[^,)]*,\s*["']([a-zA-Z0-9_]+)["']`)},
		// mcp-go.
		{framework: "mcp-go", re: regexp.MustCompile(`(?:srv|server)\.Tool\s*\(\s*["']([a-zA-Z0-9_]+)["']`)},
		// go-openai / anthropic-sdk-go function-call tools.
		{framework: "openai-go", re: regexp.MustCompile(`openai\.Tool\s*\{[^}]*Name\s*:\s*["']([a-zA-Z0-9_]+)["']`)},
	}
)

// patternsForLanguage returns the registration patterns appropriate for a
// file's extension.
func patternsForLanguage(path string) []toolPattern {
	switch {
	case strings.HasSuffix(path, ".py"):
		return pyPatterns
	case strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".jsx"),
		strings.HasSuffix(path, ".ts"), strings.HasSuffix(path, ".tsx"),
		strings.HasSuffix(path, ".mjs"), strings.HasSuffix(path, ".cjs"):
		return jsPatterns
	case strings.HasSuffix(path, ".go"):
		return goPatterns
	}
	return nil
}

// classifyToolName maps a tool name to one or more capability tags via
// substring heuristics. The matching is intentionally conservative: a name
// like "fetch_pdf" maps to http_request because the verb implies network
// fetch, even if the implementation is local.
func classifyToolName(name string) []CapabilityTag {
	low := strings.ToLower(name)
	var tags []CapabilityTag

	if containsAny(low, "shell", "exec", "run_command", "runcommand", "system_call", "subprocess", "bash") {
		tags = append(tags, CapShellExec)
	}
	switch {
	case containsAny(low, "read_file", "readfile", "fs_read", "fsread", "file_read", "fileread", "open_file", "openfile", "cat_file", "list_files", "listfiles", "ls_dir", "lsdir"):
		tags = append(tags, CapFileRead)
	case containsAny(low, "write_file", "writefile", "fs_write", "fswrite", "file_write", "filewrite", "save_file", "savefile", "append_file", "delete_file", "rm_file"):
		tags = append(tags, CapFileWrite)
	}
	switch {
	case containsAny(low, "http_request", "httprequest", "http_get", "httpget", "http_post", "httppost", "fetch_url", "fetchurl", "web_request", "fetch_pdf", "scrape", "url_fetch"):
		tags = append(tags, CapHTTPRequest)
	case containsAny(low, "send_email", "sendemail", "email_send", "emailsend", "smtp_send"):
		tags = append(tags, CapEmailSend)
	case containsAny(low, "webhook", "post_webhook", "postwebhook", "slack_send", "discord_send", "notify_webhook"):
		tags = append(tags, CapWebhookPost)
	}
	switch {
	case containsAny(low, "db_read", "dbread", "sql_query", "sqlquery", "select_query", "select_query"):
		tags = append(tags, CapDatabaseRead)
	case containsAny(low, "db_write", "dbwrite", "sql_insert", "sql_update", "sql_delete", "exec_sql", "execsql"):
		tags = append(tags, CapDatabaseWrite)
	}
	switch {
	case containsAny(low, "git_push", "gitpush", "push_repo", "pushrepo"):
		tags = append(tags, CapGitPush)
	case containsAny(low, "read_secret", "readsecret", "get_secret", "getsecret", "vault_read", "vaultread", "secrets_get", "secretsmanager_get"):
		tags = append(tags, CapReadSecret)
	}
	switch {
	case containsAny(low, "iam_attach", "iam_create_policy", "iam_put_policy", "create_role", "attach_role_policy"):
		tags = append(tags, CapCloudIAMModify)
	case containsAny(low, "stripe_charge", "create_charge", "payment_create", "init_payment", "charge_card"):
		tags = append(tags, CapPaymentInitiate)
	case containsAny(low, "human_approval", "request_approval", "ask_human", "wait_human"):
		tags = append(tags, CapHumanApproval)
	}

	if len(tags) == 0 {
		// Unknown name — leave unclassified. The lattice policy only
		// fires on tagged combinations, so unknown tools are harmless.
		return nil
	}
	return tags
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// extractTools walks the source content with the language-appropriate
// patterns and returns every tool registration found.
func extractTools(path string, content []byte) []extractedTool {
	pats := patternsForLanguage(path)
	if pats == nil {
		return nil
	}

	var tools []extractedTool
	seen := map[string]bool{}
	for _, pat := range pats {
		matches := pat.re.FindAllSubmatchIndex(content, -1)
		for _, m := range matches {
			if len(m) < 4 {
				continue
			}
			if m[2] == -1 {
				continue
			}
			name := string(content[m[2]:m[3]])
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			// Capture the description argument when present in a small
			// window after the tool name.
			desc := descriptionAfterMatch(content, m[1])
			tools = append(tools, extractedTool{
				name:        name,
				line:        lexctx.LineForOffset(content, m[0]),
				description: desc,
				tags:        classifyToolName(name),
			})
		}
	}
	return tools
}

// descriptionRe matches `description = "..."` / `description: "..."` /
// `description="..."` patterns inside a tool registration. Used to
// capture the operator/LLM-facing description string so AIBOM can audit
// description-vs-implementation drift.
var descriptionRe = regexp.MustCompile(`(?i)description\s*[:=]\s*["']([^"']{1,300})["']`)

// descriptionAfterMatch scans up to 400 bytes after the tool-name
// match for a description field. Returns "" when no description is in
// the window — most direct OpenAI / Anthropic tool registrations omit
// the description (it's set elsewhere); LangChain Tool() and similar
// pass it inline.
func descriptionAfterMatch(content []byte, start int) string {
	end := start + 400
	if end > len(content) {
		end = len(content)
	}
	if start >= len(content) {
		return ""
	}
	if m := descriptionRe.FindSubmatch(content[start:end]); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// dangerousCombo describes a forbidden-combination policy. A finding is
// emitted when the agent's tag set is a superset of Required.
type dangerousCombo struct {
	id       string
	severity findings.Severity
	required []CapabilityTag
	reason   string
	cwe      string
}

var dangerousCombos = []dangerousCombo{
	{
		id:       "AI-AGENT-001",
		severity: findings.SeverityCritical,
		required: []CapabilityTag{CapShellExec},
		reason:   "Agent exposes shell_exec — escalation primitive; combined with any tool this yields arbitrary code execution",
		cwe:      "CWE-77",
	},
	{
		id:       "AI-AGENT-002",
		severity: findings.SeverityHigh,
		required: []CapabilityTag{CapFileRead, CapHTTPRequest},
		reason:   "Agent can read files and make HTTP requests — exfiltration path: read sensitive file, post to attacker server",
		cwe:      "CWE-200",
	},
	{
		id:       "AI-AGENT-003",
		severity: findings.SeverityHigh,
		required: []CapabilityTag{CapFileRead, CapEmailSend},
		reason:   "Agent can read files and send email — exfiltration path: read sensitive file, email it out",
		cwe:      "CWE-200",
	},
	{
		id:       "AI-AGENT-004",
		severity: findings.SeverityHigh,
		required: []CapabilityTag{CapFileRead, CapWebhookPost},
		reason:   "Agent can read files and post to webhook — exfiltration path",
		cwe:      "CWE-200",
	},
	{
		id:       "AI-AGENT-005",
		severity: findings.SeverityHigh,
		required: []CapabilityTag{CapGitPush, CapReadSecret},
		reason:   "Agent can read secrets and push to git — supply-chain risk: secret leaks into commit",
		cwe:      "CWE-538",
	},
	{
		id:       "AI-AGENT-006",
		severity: findings.SeverityHigh,
		required: []CapabilityTag{CapDatabaseWrite, CapUntrustedInput},
		reason:   "Agent has database write paired with untrusted input — injection-equivalent",
		cwe:      "CWE-89",
	},
	{
		id:       "AI-AGENT-007",
		severity: findings.SeverityCritical,
		required: []CapabilityTag{CapCloudIAMModify},
		reason:   "Agent can modify cloud IAM — privilege escalation primitive",
		cwe:      "CWE-269",
	},
	{
		id:       "AI-AGENT-008",
		severity: findings.SeverityCritical,
		required: []CapabilityTag{CapPaymentInitiate},
		reason:   "Agent can initiate payments without an explicit human_approval_required tool — financial risk",
		cwe:      "CWE-840",
	},
}

// scanAgentLattice produces lattice findings for the given file.
func scanAgentLattice(path string, content []byte) []findings.Finding {
	tools := extractTools(path, content)
	if len(tools) == 0 {
		return nil
	}

	tagSet := map[CapabilityTag]bool{}
	for _, t := range tools {
		for _, tag := range t.tags {
			tagSet[tag] = true
		}
	}

	if len(tagSet) == 0 {
		return nil
	}

	var out []findings.Finding
	for i := range dangerousCombos {
		combo := &dangerousCombos[i]
		if !satisfies(tagSet, combo.required) {
			continue
		}
		// AI-AGENT-008 (payment) is only flagged when no human_approval
		// tool is present.
		if combo.id == "AI-AGENT-008" && tagSet[CapHumanApproval] {
			continue
		}

		out = append(out, findings.Finding{
			RuleID:     combo.id,
			Severity:   combo.severity,
			Confidence: findings.ConfidenceMedium,
			Location: findings.Location{
				FilePath:  path,
				StartLine: 1,
			},
			Message:  combo.reason,
			Metadata: latticeMetadata(tools, combo),
		})
	}
	return out
}

func satisfies(have map[CapabilityTag]bool, need []CapabilityTag) bool {
	for _, n := range need {
		if !have[n] {
			return false
		}
	}
	return true
}

func latticeMetadata(tools []extractedTool, combo *dangerousCombo) map[string]string {
	names := make([]string, 0, len(tools))
	described := make([]string, 0, len(tools))
	for i := range tools {
		names = append(names, tools[i].name)
		if tools[i].description != "" {
			described = append(described,
				tools[i].name+":\""+truncateDescription(tools[i].description)+"\"")
		}
	}
	sort.Strings(names)
	sort.Strings(described)

	required := make([]string, 0, len(combo.required))
	for _, t := range combo.required {
		required = append(required, string(t))
	}
	sort.Strings(required)

	md := map[string]string{
		"cwe":                  combo.cwe,
		"agent_tools":          strings.Join(names, ","),
		"violated_combination": strings.Join(required, "+"),
		"owasp":                "LLM06",
	}
	if len(described) > 0 {
		md["agent_tool_descriptions"] = strings.Join(described, " | ")
	}
	return md
}

// truncateDescription caps captured tool descriptions so finding
// metadata stays compact. AIBOM's ToolPermissionSet can carry the full
// string when needed.
func truncateDescription(s string) string {
	const maxLen = 120
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
