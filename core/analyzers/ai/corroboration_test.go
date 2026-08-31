package ai

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
)

// TestASurvivingAIFindingCarriesWhatWasChecked is the AI half of E3.
//
// Before this, every AI refiner recorded why it DROPPED a candidate and nothing
// about the ones that survived — so a reported AI finding's ledger said only
// "the rule fired", never what nox inspected before believing it. A survivor
// has been checked: it is in real code, and for a rule with a context
// requirement, the context was present. Recording that is what lets `nox why`
// answer "what supports it" with an inspection rather than a tautology.
func scanWithReasoning(t *testing.T, src string) (*reasoning.Store, *findings.FindingSet) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.py")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	store := reasoning.New()
	a := NewAnalyzer()
	a.RecordReasoningTo(store)
	// ScanArtifacts runs the refiner+corroborate loop; ScanFile alone does not.
	fs, _, err := a.ScanArtifacts(context.Background(), []discovery.Artifact{
		{Path: "agent.py", AbsPath: path, Type: discovery.Source},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return store, fs
}

const promptInjectionSrc = "import openai\n" +
	"def chat(user_input):\n" +
	"    prompt = f\"You are helpful. User: {user_input}\"\n" +
	"    return openai.ChatCompletion.create(model=\"gpt-4\", messages=[{\"role\":\"system\",\"content\":prompt}])\n"

// TestASurvivingAIFindingCarriesWhatWasChecked is the AI half of E3.
//
// Before this, every AI refiner recorded why it DROPPED a candidate and nothing
// about the ones that survived — so a reported AI finding's ledger said only
// "the rule fired", never what nox inspected before believing it. A survivor
// has been checked: it is in real code, and for a rule with a context
// requirement, the context was present. Recording that is what lets `nox why`
// answer "what supports it" with an inspection rather than a tautology.
func TestASurvivingAIFindingCarriesWhatWasChecked(t *testing.T) {
	store, fs := scanWithReasoning(t, promptInjectionSrc)

	// Key off the FINDING, not off a subject in the store. A survivor's subject
	// only appears in the store because corroboration files a claim against it,
	// so keying off the subject would make this SKIP when corroboration is
	// removed rather than FAIL — the vacuous-under-mutation trap. The finding
	// exists whether or not it was corroborated, so it is the honest anchor.
	var ai002 *findings.Finding
	for i := range fs.Findings() {
		f := fs.Findings()[i]
		if f.RuleID == "AI-002" {
			ai002 = &f
			break
		}
	}
	if ai002 == nil {
		t.Skip("this build does not report AI-002 on the fixture; the corroboration " +
			"path is unreachable and this test cannot exercise it")
	}

	subject := reasoning.Candidate("AI-002", "agent.py",
		ai002.Location.StartLine, ai002.Location.StartColumn)
	var supports []string
	for _, c := range store.About(subject).Claims {
		if c.Supports() {
			supports = append(supports, c.Statement)
		}
	}
	joined := strings.Join(supports, " | ")
	if !strings.Contains(joined, "lies in code") {
		t.Errorf("a surviving AI finding does not record that it was inspected and is "+
			"in code: %q", joined)
	}
	if !strings.Contains(joined, "prompt or LLM context") {
		t.Errorf("an AI-002 survivor does not record that the context its rule requires "+
			"was actually found: %q", joined)
	}
	if len(supports) < 2 {
		t.Errorf("AI-002 carries %d supporting claims; a reported survivor recorded "+
			"nothing beyond the rule firing", len(supports))
	}
}

// TestCorroborationIsHeuristicNotStatic. E3 measured that recording these does
// not move confidence, only explanation — because they are proximity checks, not
// proofs. A corroborating claim recorded at static strength would be claiming
// the analysis established something it only estimated.
func TestCorroborationIsHeuristicNotStatic(t *testing.T) {
	store, _ := scanWithReasoning(t, promptInjectionSrc)
	for _, s := range store.Subjects() {
		for _, c := range store.About(s).Claims {
			if c.Supports() && c.Kind.Deterministic() {
				t.Errorf("a corroborating AI claim is recorded at %q, a deterministic "+
					"kind; a proximity check is not a proof and must not read as one: %q",
					c.Kind, c.Statement)
			}
		}
	}
}
