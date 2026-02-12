package ai

import (
	"regexp"
)

// PromptTemplate represents a prompt template discovered in the codebase.
type PromptTemplate struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"` // "system", "user", "template", "file"
	Path      string   `json:"path"`
	Variables []string `json:"variables,omitempty"`
}

// extractPromptTemplates scans file content for prompt template patterns.
func extractPromptTemplates(path string, content []byte) []PromptTemplate {
	var templates []PromptTemplate
	text := string(content)
	fileName := baseName(path)

	// .prompt and .prompt.md files are templates themselves
	if hasSuffix(fileName, ".prompt") || hasSuffix(fileName, ".prompt.md") {
		tmpl := PromptTemplate{
			Name:      fileName,
			Type:      "file",
			Path:      path,
			Variables: extractTemplateVariables(text),
		}
		templates = append(templates, tmpl)
		return templates
	}

	// Detect system_prompt / system_message assignments
	systemRe := regexp.MustCompile(`(?i)(system_prompt|system_message|system_instructions|SYSTEM_PROMPT)\s*[:=]\s*(?:['"]|f['"]|""")((?:[^'"\\]|\\.)*)`)
	for _, m := range systemRe.FindAllStringSubmatch(text, -1) {
		templates = append(templates, PromptTemplate{
			Name:      m[1],
			Type:      "system",
			Path:      path,
			Variables: extractTemplateVariables(m[2]),
		})
	}

	// Detect prompt template definitions (ChatPromptTemplate, PromptTemplate)
	templateRe := regexp.MustCompile(`(?i)(ChatPromptTemplate|PromptTemplate|SystemMessagePromptTemplate)\s*\.\s*from_\w+\s*\(`)
	for _, m := range templateRe.FindAllStringSubmatch(text, -1) {
		templates = append(templates, PromptTemplate{
			Name: m[1],
			Type: "template",
			Path: path,
		})
	}

	// Detect role-based messages ({"role": "system", "content": "..."})
	roleRe := regexp.MustCompile(`(?i)["']role["']\s*:\s*["'](system|user|assistant)["']`)
	for _, m := range roleRe.FindAllStringSubmatch(text, -1) {
		templates = append(templates, PromptTemplate{
			Name: m[1] + "_message",
			Type: m[1],
			Path: path,
		})
	}

	return deduplicateTemplates(templates)
}

func extractTemplateVariables(text string) []string {
	// Match {variable_name} patterns (but not {{escaped}})
	re := regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)
	seen := make(map[string]bool)
	var vars []string
	for _, m := range re.FindAllStringSubmatch(text, -1) {
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
