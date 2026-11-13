package ai

import (
	"regexp"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/rules"
)

// PromptTemplate represents a prompt template discovered in the codebase.
type PromptTemplate struct {
	Name string `json:"name"`
	Type string `json:"type"` // "system", "user", "template", "file"
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
	// Content is a truncated copy of the prompt text (max 512 chars).
	// AIBOM consumers use this to reason about prompt-injection
	// susceptibility — without the prompt content, an inventory only
	// answers "this app uses an LLM"; with it, an inventory answers
	// "this app uses an LLM with these specific instructions and
	// these tainted input slots."
	Content   string   `json:"content,omitempty"`
	Variables []string `json:"variables,omitempty"`
}

// promptContentMaxLen caps captured prompt content so AIBOM doesn't
// balloon when a project ships large few-shot prompts.
const promptContentMaxLen = 512

func truncatePromptContent(s string) string {
	if len(s) <= promptContentMaxLen {
		return s
	}
	return s[:promptContentMaxLen] + "...[truncated]"
}

// The prompt patterns are compiled once, and those that open with literals
// are matched through the rule engine's literal-prefix plan: they are
// case-insensitive, so regexp cannot skip ahead to their literal and read
// every byte of every AI-flavoured source file (#736).
var (
	promptSystemRe      = rules.MustCompilePlanned(`(?i)(system_prompt|system_message|system_instructions|SYSTEM_PROMPT)\s*[:=]\s*(?:['"]|f['"]|""")((?:[^'"\\]|\\.)*)`)
	promptTemplateRe    = rules.MustCompilePlanned(`(?i)(ChatPromptTemplate|PromptTemplate|SystemMessagePromptTemplate)\s*\.\s*from_\w+\s*\(`)
	promptRoleContentRe = rules.MustCompilePlanned(`(?i)["']role["']\s*:\s*["'](system|user|assistant)["']\s*,\s*["']content["']\s*:\s*["']((?:[^"'\\]|\\.)*)`)
	promptRoleRe        = rules.MustCompilePlanned(`(?i)["']role["']\s*:\s*["'](system|user|assistant)["']`)
	// Match {variable_name} patterns (but not {{escaped}}).
	templateVariableRe = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)
)

// extractPromptTemplates scans file content for prompt template patterns.
// It now captures (a) the prompt content text where extractable, and
// (b) the source line number of each match so AIBOM consumers can audit
// the exact prompt that ships with the application.
func extractPromptTemplates(path string, content []byte) []PromptTemplate {
	var templates []PromptTemplate
	fileName := baseName(path)

	// .prompt and .prompt.md files are templates themselves — content
	// is the entire file, truncated.
	if hasSuffix(fileName, ".prompt") || hasSuffix(fileName, ".prompt.md") {
		text := string(content)
		tmpl := PromptTemplate{
			Name:      fileName,
			Type:      "file",
			Path:      path,
			Line:      1,
			Content:   truncatePromptContent(text),
			Variables: extractTemplateVariables(text),
		}
		templates = append(templates, tmpl)
		return templates
	}

	// Detect system_prompt / system_message assignments. Capture the
	// quoted body so AIBOM carries the actual instruction text.
	for _, m := range promptSystemRe.FindAllSubmatchIndex(content) {
		if len(m) < 6 {
			continue
		}
		name := string(content[m[2]:m[3]])
		body := string(content[m[4]:m[5]])
		templates = append(templates, PromptTemplate{
			Name:      name,
			Type:      "system",
			Path:      path,
			Line:      lexctx.LineForOffset(content, m[0]),
			Content:   truncatePromptContent(body),
			Variables: extractTemplateVariables(body),
		})
	}

	// Detect prompt template definitions (ChatPromptTemplate, PromptTemplate).
	for _, m := range promptTemplateRe.FindAllSubmatchIndex(content) {
		if len(m) < 4 {
			continue
		}
		templates = append(templates, PromptTemplate{
			Name: string(content[m[2]:m[3]]),
			Type: "template",
			Path: path,
			Line: lexctx.LineForOffset(content, m[0]),
		})
	}

	// Detect role-based messages with inline content
	// ({"role": "system", "content": "..."}). Capture the content
	// string when present.
	for _, m := range promptRoleContentRe.FindAllSubmatchIndex(content) {
		if len(m) < 6 {
			continue
		}
		role := string(content[m[2]:m[3]])
		body := string(content[m[4]:m[5]])
		templates = append(templates, PromptTemplate{
			Name:      role + "_message",
			Type:      role,
			Path:      path,
			Line:      lexctx.LineForOffset(content, m[0]),
			Content:   truncatePromptContent(body),
			Variables: extractTemplateVariables(body),
		})
	}

	// Bare role markers without inline content (multi-line message
	// objects).
	for _, m := range promptRoleRe.FindAllSubmatchIndex(content) {
		if len(m) < 4 {
			continue
		}
		templates = append(templates, PromptTemplate{
			Name: string(content[m[2]:m[3]]) + "_message",
			Type: string(content[m[2]:m[3]]),
			Path: path,
			Line: lexctx.LineForOffset(content, m[0]),
		})
	}

	return deduplicateTemplates(templates)
}

func extractTemplateVariables(text string) []string {
	seen := make(map[string]bool)
	var vars []string
	for _, m := range templateVariableRe.FindAllStringSubmatch(text, -1) {
		name := m[1]
		if !seen[name] && !isCommonBrace(name) {
			seen[name] = true
			vars = append(vars, name)
		}
	}
	return vars
}

func isCommonBrace(name string) bool {
	// Filter out common non-variable braces
	common := []string{"0", "1", "2", "3", "n", "s", "d", "f", "r", "t"}
	for _, c := range common {
		if name == c {
			return true
		}
	}
	return false
}

func deduplicateTemplates(templates []PromptTemplate) []PromptTemplate {
	seen := make(map[string]bool)
	var unique []PromptTemplate
	for _, t := range templates {
		key := t.Name + "|" + t.Type + "|" + t.Path
		if !seen[key] {
			seen[key] = true
			unique = append(unique, t)
		}
	}
	return unique
}
