package ai

import "testing"

// TestAI022_ReasoningModelTemperatureIsSafe covers AI-022 ("LLM temperature
// set too high, allowing hallucination") firing on OpenAI o1/o3 reasoning
// model configs where temperature=1.0 is the expected default, not a
// misconfiguration. Discovered during the scan-of-the-week for
// princeton-nlp/SWE-agent (commit 3ea751c).
//
// Two suppression contexts:
//   - reasoning_effort nearby: the model is an o1/o3 reasoning model;
//     temperature semantics differ from standard models.
//   - "name: replay" nearby: the entry is a test-replay driver, not a real
//     LLM call path.
//
// The want:true cases guard that neither suppression swallows a real finding.
func TestAI022_ReasoningModelTemperatureIsSafe(t *testing.T) {
	cases := []struct {
		name string
		file string
		src  string
		want bool
	}{
		{
			name: "plain high temperature fires",
			file: "config.yaml",
			src:  "model:\n  name: gpt-4\n  temperature: 1.0\n",
			want: true,
		},
		{
			name: "reasoning_effort nearby suppresses",
			file: "benchmark.yaml",
			src:  "model:\n  name: o1\n  temperature: 1.\n  completion_kwargs:\n    reasoning_effort: \"high\"\n",
			want: false,
		},
		{
			name: "replay model name nearby suppresses",
			file: "trajectory.yaml",
			src:  "model:\n  name: replay\n  temperature: 1.0\n  top_p: 1.0\n",
			want: false,
		},
		{
			// reasoning_effort outside the context window must not suppress a
			// distant standard-model temperature setting.
			name: "reasoning_effort too far away does not suppress",
			file: "multi.yaml",
			src:  "chooser:\n  reasoning_effort: high\n\n\n\n\n\nagent:\n  name: gpt-4\n  temperature: 1.0\n",
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got bool
			for _, f := range scanOneAI(t, tc.file, tc.src) {
				if f.RuleID == "AI-022" {
					got = true
				}
			}
			if got != tc.want {
				if tc.want {
					t.Fatalf("AI-022 stopped firing on a plain high-temperature config "+
						"(regression — suppression is too broad):\n%s", tc.src)
				}
				t.Fatalf("AI-022 fired on a config where temperature=1.0 is safe "+
					"(false positive):\n%s", tc.src)
			}
		})
	}
}
