package main

import (
	"strings"
	"testing"
)

// TestPrevalenceRenderSeparatesTheTiers is the guard on the distinction that
// reading a single number has already got wrong here: AI-029 measured 446 raw
// findings on crewAI and 26 authored occurrences, and only the second number
// described anything a person could act on.
func TestPrevalenceRenderSeparatesTheTiers(t *testing.T) {
	t.Parallel()

	report := &BenchReport{
		RulePrevalence: map[string]*RulePrevalence{
			// A documentation-multiplied rule: loud raw, quiet authored.
			"AI-029": {Repos: 1, Findings: 446, Sites: 26},
			// A broad, quiet rule: FEWER raw findings than AI-029 but MORE
			// authored occurrences. The two orderings disagree here, which is
			// the only way this test can tell which one the table used.
			"SEC-001": {Repos: 7, Findings: 40, Sites: 40},
			// Tier 3 present: a rule that declared what its finding is about.
			// 65 findings over 65 pins to add, so conditions == findings here,
			// which is the CORRECT answer and not a failure to collapse.
			"IAC-211": {Repos: 1, Findings: 65, Sites: 65, Subjects: 65},
		},
	}
	var b strings.Builder
	renderPrevalence(&b, report)
	out := b.String()

	for _, want := range []string{"446", "26", "17.2x", "not declared"} {
		if !strings.Contains(out, want) {
			t.Errorf("prevalence table is missing %q:\n%s", want, out)
		}
	}
	// AI-029 has 446 raw against SEC-001's 40, but 26 authored against 40. A
	// table ranked on raw findings puts AI-029 first; one ranked on authored
	// occurrences puts SEC-001 first. That disagreement is the assertion.
	if strings.Index(out, "| SEC-001 ") > strings.Index(out, "| AI-029 ") {
		t.Errorf("AI-029 (446 raw, 26 authored) ranked above SEC-001 (40 raw, 40 authored) — "+
			"the table is ranking on raw findings:\n%s", out)
	}
	// A rule that declared a subject prints its count; one that did not must
	// print "not declared" rather than 0, so "none found" and "never asked"
	// stay distinguishable.
	if !strings.Contains(out, "| IAC-211 | 1 | 65 | 65 | — | 65 |") {
		t.Errorf("IAC-211 declared a subject and should show its condition count:\n%s", out)
	}
	// A rule with no copies must not claim a copy factor.
	if !strings.Contains(out, "| SEC-001 | 7 | 40 | 40 | — |") {
		t.Errorf("SEC-001 should show no copy factor:\n%s", out)
	}
}
