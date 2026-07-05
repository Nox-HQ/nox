package ai

import (
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// promptContextTokens are markers of an actual prompt / LLM-call context. AI-002
// (user input concatenated into a prompt template) is only a real
// prompt-injection risk when the surrounding code is building or sending a
// prompt — not when the same `f"…{user_input}"` / `%s … user_input` shape
// appears in a SQL query, a log line, or a shell command. These tokens mirror
// the vocabulary of the major LLM SDKs (OpenAI, Anthropic, LangChain, ...).
var promptContextTokens = []string{
	"prompt",
	"messages",
	".chat.",
	".completions.",
	"completion",
	"system_prompt",
	"system prompt",
	"llm",
	"openai",
	"anthropic",
	"claude",
	"gpt",
	"langchain",
	"generate(",
	"invoke(",
	"chatprompt",
	"prompttemplate",
	"role\":",
	"role':",
	"role=",
}

// promptContextWindow is the number of source lines above and below the match
// searched for a prompt-context token. A prompt is usually assembled within a
// few lines of where user input is interpolated.
const promptContextWindow = 4

// hasPromptContext reports whether an AI-002 finding sits in genuine
// prompt/LLM-building context. It scans a small window of lines around the
// match (case-insensitively) for any promptContextToken. This tightens AI-002
// from "any string concat with user_input" to "string concat with user_input
// in a prompt", eliminating the parameterised-SQL false positive without
// dropping the real f-string prompt-injection positive.
func hasPromptContext(content []byte, f *findings.Finding) bool {
	loStart := f.Location.StartLine - promptContextWindow
	if loStart < 1 {
		loStart = 1
	}
	hiEnd := f.Location.EndLine + promptContextWindow
	start := lexctx.LineColToOffset(content, loStart, 1)
	end := lexctx.LineColToOffset(content, hiEnd+1, 1)
	if end <= start || end > len(content) {
		end = len(content)
	}
	window := strings.ToLower(string(content[start:end]))
	for _, tok := range promptContextTokens {
		if strings.Contains(window, tok) {
			return true
		}
	}
	return false
}
