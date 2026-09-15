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

// aiFired reports whether rule fired on body.
func aiFired(t *testing.T, rule, body string) bool {
	t.Helper()
	got, err := NewAnalyzer().ScanFile("agent.py", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

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

// AI-019 is the other kind of defect in this family, and it is a fix rather
// than a removal: a real supply-chain proposition expressed badly.
//
// "Model loaded without hash verification" matched `from_pretrained(` and
// stopped at the paren, so it never saw the arguments — a pinned load was
// reported exactly like an unpinned one, and the rule's name asserted
// something its pattern had not established. Of 99 model loads across the
// fourteen pinned repositories, zero carry a pin, so the rule was right about
// every one of them for a reason it could not give.
func TestAI019ReportsAnUnpinnedLoad(t *testing.T) {
	for _, line := range []string{
		`model = AutoModel.from_pretrained("bert-base-uncased")`,
		`pipeline("sentiment-analysis")`,
		`m = load_model("weights")`,
	} {
		if !aiFired(t, "AI-019", line+"\n") {
			t.Errorf("AI-019 stopped reporting an unpinned model load: %s", line)
		}
	}
}

// The half the rule could not previously express. A project that does what the
// remediation asks must stop being told it has not.
func TestAI019AcceptsAPinnedLoad(t *testing.T) {
	for name, src := range map[string]string{
		"same line": `m = AutoModel.from_pretrained("bert-base-uncased", revision="a1b2c3d4e5f6")` + "\n",
		"multi line": "m = AutoModel.from_pretrained(\n" +
			"    \"bert-base-uncased\",\n" +
			"    revision=\"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\",\n" +
			")\n",
		"digest":   `m = load_model("weights", checksum="sha256:deadbeef")` + "\n",
		"no fetch": `m = AutoModel.from_pretrained("./local", local_files_only=True)` + "\n",
	} {
		if aiFired(t, "AI-019", src) {
			t.Errorf("AI-019 reported a pinned load (%s) as unverified:\n%s", name, src)
		}
	}
}
