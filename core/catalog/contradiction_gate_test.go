package catalog

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/rules"
)

// TestNoBuiltinRuleContradictsItsOwnRemediation is a hard gate, and the only
// rule-review signal promoted to one.
//
// The invariant: a rule must not prescribe as its remedy the condition it
// reports as insecure. An operator who follows the remediation to the letter
// must end up with the finding gone, and a rule whose recommended range
// CONTAINS the value its trigger requires cannot promise that.
//
// AI-029 is why. It flagged `presence_penalty = 0` as "repetition penalties
// disabled" while advising "Set presence_penalty (-2 to 0)", and it fired 446
// times on the pinned corpus before anyone read the two strings next to each
// other.
//
// # Why this one and not the other two
//
// The promotion is earned, not granted by symmetry. This signal is
// mechanically checkable from the rule alone — no corpus, no scan, no
// judgement about how much of anything is too much — and measured against the
// catalogue as it stood before the withdrawal (1,498 rules at 9c5aea8^) it
// reported AI-029 and nothing else: one true positive, zero false positives.
//
// The other two signals stay informational and must not be promoted by
// analogy. `single_construct` reports a gap in the CORPUS, not a defect in the
// rule, and the remedy is usually a second test input. Prevalence collapse
// reports that a corpus repeats what a rule correctly detects; a correct rule
// fires as often as the thing it detects appears. Failing a build on either
// would be failing it on a measurement that is not about the rule being wrong.
// See docs/design/rule-review-candidates.md.
//
// # Scope
//
// Built-in rules only. This deliberately does NOT run inside CheckCoherence,
// which refuses a rule at load time: an operator's own custom rule with loose
// remediation wording would then fail to load and take their scan down with
// it. A wording smell must not be able to stop somebody's scanner. The gate
// belongs to this repository's catalogue, where the cost of a failure is a red
// build and the fix is an edit to a string.
func TestNoBuiltinRuleContradictsItsOwnRemediation(t *testing.T) {
	analysed := 0
	for _, r := range Rules() {
		if r.Pattern == "" || r.Remediation == "" {
			continue
		}
		if _, _, ok := r.PinnedAssignment(); ok {
			analysed++
		}
		c, ok := r.RemediationContradiction()
		if !ok {
			continue
		}
		t.Errorf("%s prescribes the condition it reports.\n"+
			"  trigger fires on:  %s = %s\n"+
			"  remediation endorses %q for %s, a range containing %s\n"+
			"  remediation: %s\n"+
			"Following this advice can leave the finding in place. Either the "+
			"trigger is pinned to the wrong value, or the remediation recommends "+
			"the wrong range — fix whichever is wrong rather than silencing this.",
			r.ID, c.Param, c.Flagged, c.Endorsement, c.Param, c.Flagged, r.Remediation)
	}

	// A floor, not an equality: a gate that analysed nothing would pass, and
	// would keep passing while the analysis quietly stopped working. 189 rules
	// pinned a parameter to a literal when this landed.
	if analysed < 100 {
		t.Errorf("only %d rules pin a parameter to a literal value; the scanner "+
			"has stopped reading patterns it used to read, so this gate is "+
			"passing over nearly nothing", analysed)
	}
}

// TestTheGateWouldHaveCaughtAI029 keeps the gate from becoming a tautology.
//
// A gate that asserts "zero" over a catalogue that happens to contain zero is
// indistinguishable from a gate whose detector is broken. This feeds the
// withdrawn rule's verbatim definition through the same path the gate uses and
// requires it to fail, so the gate's teeth are asserted rather than assumed.
func TestTheGateWouldHaveCaughtAI029(t *testing.T) {
	withdrawn := &rules.Rule{
		ID:          "AI-029",
		Pattern:     `(?im)(?:presence_penalty|frequency_penalty)["']?\s*[:=]\s*0(?:\.0+)?(?:[\s,)\]}]|$)`,
		Remediation: "Set presence_penalty (-2 to 0) and frequency_penalty (-2 to 0) to reduce repetitive token generation. Default values of 0 may allow excessive repetition.",
	}
	c, ok := withdrawn.RemediationContradiction()
	if !ok {
		t.Fatal("the gate no longer detects AI-029, so its zero result means nothing")
	}
	if !strings.Contains(c.Endorsement, "-2 to 0") {
		t.Errorf("endorsement %q does not quote the range it read", c.Endorsement)
	}
}

// TestNoBuiltinRuleAdvisesWhatAnotherFlags is the cross-rule half of the same
// invariant: following nox's own advice must not produce another nox finding.
//
// AI-023 and AI-041 shipped as such a pair for months. AI-023 advised "Use
// top_p of 0.7-0.95 for balanced output"; AI-041 fired on `top_p: 0.95`. An
// operator who did exactly what one rule said got a finding from the other.
//
// It was resolved incidentally — AI-041 was withdrawn in v1.36.0 for an
// unrelated reason — which is the whole argument for checking this
// mechanically. Nobody read the two remediations side by side in all that
// time, and there are 1,496 rules.
func TestNoBuiltinRuleAdvisesWhatAnotherFlags(t *testing.T) {
	for _, c := range rules.CrossContradictions(Rules()) {
		t.Errorf("%s advises a value %s reports as a defect.\n"+
			"  %s remediation endorses %q for %s\n"+
			"  %s fires on %q\n"+
			"An operator who follows %s gets a %s finding for it. Either the "+
			"advice or the trigger is wrong; they cannot both be right.",
			c.Adviser, c.Flagger, c.Adviser, c.Endorsement, c.Param,
			c.Flagger, c.Assignment, c.Adviser, c.Flagger)
	}
}

// TestTheCrossGateWouldHaveCaughtTheShippedPair asserts the gate's teeth for
// the same reason its intra-rule sibling does: a zero over a catalogue that
// contains zero proves nothing about the detector.
func TestTheCrossGateWouldHaveCaughtTheShippedPair(t *testing.T) {
	shipped := []*rules.Rule{
		{
			ID:          "AI-023",
			Pattern:     `(?i)(top_p\s*[:=]\s*0\.[0-6][0-9]?)`,
			Remediation: "Use top_p of 0.7-0.95 for balanced output. Lower values (0.1-0.3) may cause repetitive responses and reduce response quality.",
		},
		{
			ID:          "AI-041",
			Pattern:     `(?i)(temperature|top_p)\s*[:=]\s*(?:0\.9[0-9]*[1-9]|1\.0+)`,
			Remediation: "High temperature (>0.9) increases randomness and reduces consistency. Use 0.1-0.3 for deterministic outputs.",
		},
	}
	got := rules.CrossContradictions(shipped)
	if len(got) != 1 {
		t.Fatalf("the cross gate no longer detects the AI-023/AI-041 pair, so its "+
			"zero result over the catalogue means nothing: %+v", got)
	}
	if got[0].Adviser != "AI-023" || got[0].Flagger != "AI-041" {
		t.Errorf("direction is %s -> %s, want AI-023 -> AI-041",
			got[0].Adviser, got[0].Flagger)
	}
}
