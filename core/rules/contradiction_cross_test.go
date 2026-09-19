package rules

import (
	"regexp"
	"testing"
)

// retiredAI023Pair is the AI-023 / AI-041 pair as it shipped, verbatim.
//
// Neither is in the catalogue any more: AI-041 was withdrawn in v1.36.0 for an
// unrelated reason, which is what resolved this pair, and AI-023 followed in
// v1.38.0. Both definitions are kept here because the pair is the only worked
// example this check has, and a check whose one example is not asserted is a
// check nobody can trust.
func retiredAI023Pair() []*Rule {
	return []*Rule{
		{
			ID:          "AI-023",
			Pattern:     `(?i)(top_p\s*[:=]\s*0\.[0-6][0-9]?)`,
			Description: "LLM top_p set too low, reducing output diversity",
			Remediation: "Use top_p of 0.7-0.95 for balanced output. Lower values (0.1-0.3) may cause repetitive responses and reduce response quality.",
		},
		{
			ID:          "AI-041",
			Pattern:     `(?i)(temperature|top_p)\s*[:=]\s*(?:0\.9[0-9]*[1-9]|1\.0+)`,
			Description: "AI model uses high temperature/top_p settings",
			Remediation: "High temperature (>0.9) increases randomness and reduces consistency. Use 0.1-0.3 for deterministic outputs.",
		},
	}
}

// TestTheShippedPairIsFound is the acceptance test.
//
// Note the DIRECTION, which the first hand-written account of this pair got
// backwards. AI-023 is the adviser: its remediation says "Use top_p of
// 0.7-0.95", and AI-041 fires on the top of that range. AI-041's own
// remediation recommends 0.1-0.3, but it says so next to the word
// "temperature", not "top_p", so it endorses nothing for this parameter.
//
// Reading the ranges out of prose by proximity is what makes that distinction,
// and asserting it here is what stops a later "simplification" from widening
// the search to any number anywhere in the text.
func TestTheShippedPairIsFound(t *testing.T) {
	got := CrossContradictions(retiredAI023Pair())
	if len(got) != 1 {
		t.Fatalf("got %d pairs, want exactly 1: %+v", len(got), got)
	}
	c := got[0]
	if c.Adviser != "AI-023" || c.Flagger != "AI-041" {
		t.Errorf("direction is %s -> %s, want AI-023 -> AI-041", c.Adviser, c.Flagger)
	}
	if c.Param != "top_p" {
		t.Errorf("param %q, want top_p", c.Param)
	}
	if c.Endorsement != "0.7-0.95" {
		t.Errorf("endorsement %q, want the range read from AI-023's prose", c.Endorsement)
	}
	// The reported value must actually reproduce the finding, or the evidence
	// handed to a maintainer is not checkable.
	flagger := retiredAI023Pair()[1]
	if !mustCompile(t, flagger.Pattern).MatchString(c.Assignment) {
		t.Errorf("reported assignment %q does not match %s's pattern", c.Assignment, c.Flagger)
	}
}

// TestAConsistentPairIsNotReported guards the direction that matters: a check
// that reports pairs too eagerly makes every remediation suspect.
func TestAConsistentPairIsNotReported(t *testing.T) {
	consistent := []*Rule{
		{
			ID:          "A-1",
			Pattern:     `(?i)top_p\s*[:=]\s*0\.[0-6][0-9]?`,
			Remediation: "Use top_p of 0.7-0.95 for balanced output.",
		},
		{
			// Flags only ABOVE the adviser's range, so following the advice is safe.
			ID:          "B-1",
			Pattern:     `(?i)top_p\s*[:=]\s*(?:0\.9[6-9]|1\.0+)`,
			Remediation: "Lower top_p.",
		},
	}
	if got := CrossContradictions(consistent); len(got) != 0 {
		t.Fatalf("reported %+v for two rules whose ranges do not overlap", got)
	}
}

// TestOnePairIsOneFinding keeps the spelling sweep from inflating the count.
func TestOnePairIsOneFinding(t *testing.T) {
	got := CrossContradictions(retiredAI023Pair())
	if len(got) != 1 {
		t.Fatalf("got %d findings for one pair; the spellings are being counted "+
			"separately: %+v", len(got), got)
	}
}

// TestSamplingCoversTheInteriorOfARange is why endpoints alone are not enough:
// a flagging rule may cover only a slice in the middle of what is advised.
func TestSamplingCoversTheInteriorOfARange(t *testing.T) {
	interior := []*Rule{
		{
			ID:          "ADVISE-1",
			Pattern:     `(?i)ratio\s*[:=]\s*9`,
			Remediation: "Set ratio between 0 and 1 for best results.",
		},
		{
			// Fires only around the middle of 0..1, which both endpoints miss.
			ID:      "FLAG-1",
			Pattern: `(?i)ratio\s*[:=]\s*0\.[45]`,
		},
	}
	got := CrossContradictions(interior)
	if len(got) != 1 {
		t.Fatalf("an interior-only overlap was missed; endpoint-only sampling "+
			"has crept back in: %+v", got)
	}
}

func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return re
}
