package ai

import (
	"strings"
	"testing"
)

// AI-034 says "forced to use tool calls". On openai-python at the pinned bench
// commit it produced 10 findings and none described that: six were
// `tool_choice="auto"`, the API default in which the model decides, and four
// were `tool_choice:` on a line of its own with the JSON-schema keyword `anyOf`
// on the next — `\s*` crossed the newline and `any` matched inside `anyOf`.
func TestAI034FiresOnlyWhenACallIsForced(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
		want bool
	}{
		{"required forces a call", `resp = client.chat.completions.create(tool_choice="required")`, true},
		{"any forces a call", `tool_choice: any`, true},
		{"auto is the default and lets the model decide", `resp = client.chat.completions.create(tool_choice="auto")`, false},
		{"none disables tools", `tool_choice="none"`, false},
		{"anyOf on the next line is a schema keyword", strings.Join([]string{
			"            tool_choice:",
			"              anyOf:",
			"              - $ref: '#/components/schemas/ToolChoiceParam'",
		}, "\n"), false},
		{"anything prefixed any is not any", `tool_choice: anything_goes`, false},
	}
	for _, tc := range cases {
		got, err := NewAnalyzer().ScanFile("agent.py", []byte(tc.body))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		fired := false
		for i := range got {
			if got[i].RuleID == "AI-034" {
				fired = true
			}
		}
		if fired != tc.want {
			t.Errorf("%s: AI-034 fired=%v, want %v", tc.name, fired, tc.want)
		}
	}
}
