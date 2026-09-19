package ai

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/rules"
)

// AI-022, AI-023, AI-028 and AI-037 were withdrawn in v1.38.1 on the standard
// v1.36.0 set for AI-029 and AI-041: a rule must state a confidentiality,
// integrity or availability claim, and "differs from a tuning recommendation" is
// not one.
//
// AI-022 was the one that could not stand beside that precedent. AI-041 was
// withdrawn for flagging temperature above 0.9; AI-022 flagged 0.8 and up, a
// strict superset, at High severity — and 1.0 is the default of the OpenAI and
// Anthropic APIs and the only temperature o1/o3 accept, which is how the
// scan-of-the-week on SWE-agent found it firing on reasoning-model configs.
//
// AI-024 (stop sequences, "unwanted content types") and AI-050 (retries
// disabled, an availability claim) stay: each states a claim, however weak, and
// `nox rule-review` is where a maintainer reads them again.

func TestWithdrawnReliabilityRulesStayWithdrawn(t *testing.T) {
	t.Parallel()

	withdrawn := []string{"AI-022", "AI-023", "AI-028", "AI-037"}
	live := map[string]bool{}
	for _, r := range builtinAIRules() {
		live[r.ID] = true
	}
	for _, id := range withdrawn {
		if live[id] {
			t.Errorf("%s is back in the rule set. If it has a security proposition now, write it "+
				"as a new rule with evidence and tests rather than restoring this one.", id)
		}
		// The tombstone is what turns a vanished rule into an explanation for
		// anyone holding a waiver, baseline entry or VEX statement naming it.
		if _, ok := rules.Withdrawn(id); !ok {
			t.Errorf("%s has no tombstone, so a waiver naming it goes silent instead of explaining", id)
		}
	}
}

// The behavioural half: the exact configurations these rules reported must
// produce no finding from any rule. Asserting on rule IDs alone would pass if a
// sibling picked the same lines up.
func TestTuningConfigurationIsNotASecurityFinding(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		// SWE-agent's benchmark config: o1 only accepts temperature 1.
		"reasoning model": strings.Join([]string{
			"agent:",
			"  model:",
			"    name: o1",
			"    temperature: 1.",
			"    completion_kwargs:",
			`      reasoning_effort: "high"`,
		}, "\n"),
		"vendor defaults": strings.Join([]string{
			"client.chat.completions.create(",
			`    model="gpt-4o",`,
			"    temperature=1.0,",
			"    top_p=0.5,",
			"    seed=None,",
			")",
		}, "\n"),
		"long system prompt": `system = "` + strings.Repeat("You are careful. ", 150) + `"`,
	}
	for name, body := range cases {
		got, err := NewAnalyzer().ScanFile("config.py", []byte(body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i := range got {
			t.Errorf("%s: %s reported tuning configuration as a security finding: %s",
				name, got[i].RuleID, got[i].Message)
		}
	}
}
