package ai

import (
	"bytes"
	"regexp"

	"github.com/nox-hq/nox/core/findings"
)

// agentInputKey matches a key or keyword argument that carries an agent's
// input, up to and including the quote that opens its value: `input="`,
// `"input": "`, `prompt='`, `user_message=f"`. Group 1 is that opening quote.
//
// The names are the ones that feed a model a user turn. None of them holds
// tool metadata: a poisoned MCP tool reaches the model through a description,
// an instructions field or a docstring, never through `input=`.
var agentInputKey = regexp.MustCompile(
	`(?i)(?:^|[^\w])["']?(?:input|prompt|query|question|user_input|user_message|user_prompt)["']?\s*[:=]\s*[fbru]{0,2}(["'` + "`" + `])`)

// isAgentInputValue reports whether an MCP-009/010 match lies inside the string
// literal that is the value of an agent-input key on the same line.
//
// MCP-009 and MCP-010 describe themselves as "MCP tool metadata contains ...".
// A phrase fed to an agent as its input is a test of an injection defence —
// phidata's guardrail cookbook passes "Ignore previous instructions ..." that
// way three times — not metadata. #474 excused code that DETECTS injection by
// naming words near the match; this is the other half, and it is structural
// rather than proximate: the literal must be the value of that key, still open
// at the match. A description following an input key on the same line, or an
// input literal that closed before the phrase, is not excused.
func isAgentInputValue(content []byte, r *findings.Finding) bool {
	line := lineText(content, r.Location.StartLine)
	col := r.Location.StartColumn - 1
	if col <= 0 || col > len(line) {
		return false
	}
	prefix := line[:col]
	locs := agentInputKey.FindAllSubmatchIndex(prefix, -1)
	if len(locs) == 0 {
		return false
	}
	last := locs[len(locs)-1]
	quote := prefix[last[2]:last[3]]
	// The value must still be open at the match: no closing quote between the
	// opening one and the phrase.
	return !bytes.Contains(prefix[last[3]:], quote)
}

// lineText returns the 1-based line n of content, without its newline.
func lineText(content []byte, n int) []byte {
	for i := 1; i < n; i++ {
		j := bytes.IndexByte(content, '\n')
		if j < 0 {
			return nil
		}
		content = content[j+1:]
	}
	if j := bytes.IndexByte(content, '\n'); j >= 0 {
		return content[:j]
	}
	return content
}
