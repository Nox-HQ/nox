package ai

import (
	"testing"
)

// This file used to pin the precision of AI-029 and AI-041 — two sampling-
// parameter rules that reported the opposite of what they claimed. AI-029 said
// "repetition penalties disabled" and matched `presence_penalty=0.1`; AI-041
// said "temperature/top_p above 0.9" and matched exactly 0.9. Both were fixed,
// and fixing them raised the question the fix could not answer: what makes a
// sampling parameter a security finding at all?
//
// It does not. Twelve rules in this family reported a model-configuration
// preference rather than a security condition, and three refuted themselves
// without leaving the rule table — AI-023 and AI-041 demanded contradictory
// values of `top_p`, AI-034 fired on every legal value of `tool_choice`, and
// AI-029's remediation named the value it reported. They were removed. See
// docs/design/ai-rule-proposition.md for the decision and the evidence.
//
// The test below is what remains: the removal has to stay removed, and anyone
// re-adding one of these IDs should have to read why it went.

// removedAsConfigurationPreference lists the AI rule IDs removed because they
// report a configuration choice, not an attacker-reachable consequence.
var removedAsConfigurationPreference = []string{
	"AI-022", // temperature >= 0.8
	"AI-023", // top_p <= 0.69  (contradicts AI-041)
	"AI-024", // empty stop-sequence list
	"AI-028", // no seed set
	"AI-029", // presence/frequency penalty == 0, the vendor default
	"AI-034", // tool_choice in {any, auto, required} — every legal value
	"AI-036", // gpt-3.5 named anywhere in the file
	"AI-037", // system prompt longer than 2000 characters
	"AI-041", // temperature/top_p > 0.9  (contradicts AI-023)
	"AI-044", // context window "very high"
	"AI-048", // response caching disabled
	"AI-050", // retries disabled
}

func TestConfigurationPreferencesAreNotRules(t *testing.T) {
	live := map[string]bool{}
	for _, r := range builtinAIRules() {
		live[r.ID] = true
	}
	for _, id := range removedAsConfigurationPreference {
		if live[id] {
			t.Errorf("%s is back in the rule table. It reports a model-configuration "+
				"preference, not a security condition: a value differing from a "+
				"recommendation is not a vulnerability, and a vendor default is not one "+
				"by construction. Read docs/design/ai-rule-proposition.md before "+
				"re-adding it.", id)
		}
	}
}

// TestSurvivingConfigRulesReportARemovedProtection is the other half of the
// decision, and the one that makes it a line rather than a cull. Four rules in
// the same neighbourhood look like configuration checks and were kept, because
// each reports a protection switched OFF rather than a value tuned. If one of
// these disappears, the boundary moved and the doc is stale.
func TestSurvivingConfigRulesReportARemovedProtection(t *testing.T) {
	live := map[string]bool{}
	for _, r := range builtinAIRules() {
		live[r.ID] = true
	}
	for id, why := range map[string]string{
		"AI-017": "max_tokens unbounded is generation cost an attacker can drive",
		"AI-035": "max_iterations 0/-1/None removes the bound on an agent loop",
		"AI-033": "content filtering set to false is a safety boundary switched off",
		"AI-046": "input sanitisation disabled is the prompt-injection guard switched off",
	} {
		if !live[id] {
			t.Errorf("%s was removed, but it is on the keep side of the line in "+
				"docs/design/ai-rule-proposition.md: %s", id, why)
		}
	}
}
