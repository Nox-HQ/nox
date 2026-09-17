package rules

import (
	"fmt"
	"testing"
)

// A rule declares what its finding is ABOUT, because no definition derived from
// where the finding landed is right for both of the cases this was measured on
// (docs/design/condition-dedup.md):
//
//   - IAC-211 reports three unpinned Galaxy roles in ONE requirements.yml
//     block. Three pins to add, so three subjects, though they share a block.
//   - An LLM tuning rule reporting `frequency_penalty=0.0` and
//     `presence_penalty=0.0` on consecutive lines reports ONE decision, so one
//     subject, though the matched text differs.
//
// A construct-keyed subject merges the first; a value-keyed subject splits the
// second. These two tests are those two cases.

func subjectsOf(t *testing.T, kind, content, pattern string) map[string]int {
	t.Helper()

	rule := &Rule{ID: "TEST", MatcherType: "regex", Pattern: pattern,
		Metadata: map[string]string{SubjectKindKey: kind}}
	rs := NewRuleSet()
	rs.Add(rule)
	got, err := NewEngine(rs).ScanFile("f.yml", []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for i := range got {
		out[got[i].Metadata[SubjectIDKey]]++
	}
	if len(got) == 0 {
		t.Fatal("the fixture produced no findings, so this test measured nothing")
	}
	return out
}

func TestAValueSubjectSeparatesSiblingsInOneBlock(t *testing.T) {
	t.Parallel()

	// The shape IAC-211 meets: one block, three roles, three pins.
	content := "roles:\n  - name: geerlingguy.apache\n  - name: geerlingguy.firewall\n  - name: geerlingguy.haproxy\n"
	subs := subjectsOf(t, "value", content, `name: [a-z.]+`)
	if len(subs) != 3 {
		t.Errorf("three unpinned roles in one block are three pins to add, got %d subject(s): %v",
			len(subs), subs)
	}
}

func TestAConstructSubjectJoinsLinesOfOneDecision(t *testing.T) {
	t.Parallel()

	// The shape AI-029 met: one call, two parameters, one decision.
	content := "llm = LLM(\n    frequency_penalty=0.0,\n    presence_penalty=0.0,\n)\n"
	subs := subjectsOf(t, "construct", content, `(?:frequency|presence)_penalty=0\.0`)
	if len(subs) != 1 {
		t.Errorf("two parameters of one configuration call are one decision, got %d subject(s): %v",
			len(subs), subs)
	}
}

func TestAnUndeclaredRuleGetsNoSubject(t *testing.T) {
	t.Parallel()

	rule := &Rule{ID: "TEST", MatcherType: "regex", Pattern: `name: [a-z.]+`}
	rs := NewRuleSet()
	rs.Add(rule)
	got, err := NewEngine(rs).ScanFile("f.yml", []byte("roles:\n  - name: geerlingguy.apache\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("fixture produced no findings")
	}
	for i := range got {
		if id := got[i].Metadata[SubjectIDKey]; id != "" {
			t.Errorf("a rule that declared no subject was given one anyway: %q", id)
		}
	}
	_ = fmt.Sprint()
}
