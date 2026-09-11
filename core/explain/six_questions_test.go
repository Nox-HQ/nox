package explain_test

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/explain"
)

// Milestone 11.3: every important result answers the six questions.
//
// Five had fields. The sixth — what would move this conclusion — was appended
// to the remediation string, which conflated two questions with different
// readers: remediation is for whoever fixes the finding, this is for whoever
// decides whether to trust the verdict. A consumer reading the JSON could not
// get it without parsing prose off the end of another field.
func TestAllSixQuestionsAreAnswered(t *testing.T) {
	in := baseInputs()
	in.Registry = capability.DefaultRegistry()
	e := explain.Explain(in)

	for name, answer := range map[string]string{
		"what was observed":    e.Observed,
		"what it means here":   e.AffectsThisApplication,
		"what would change it": e.WhatWouldChangeIt,
	} {
		if strings.TrimSpace(answer) == "" {
			t.Errorf("%q is unanswered", name)
		}
	}
	for name, answer := range map[string][]string{
		"what supports it":       e.Supports,
		"what refutes it":        e.Against,
		"what was not evaluated": e.NotEvaluated,
	} {
		if len(answer) == 0 {
			t.Errorf("%q is unanswered", name)
		}
	}
}

// The sixth question is answered in every case, including the two where there
// is nothing to recommend.
//
// Returning "" for those — as it did while glued to the remediation — leaves
// the reader to supply their own answer, and the comfortable one is that there
// is nothing more to know.
func TestWhatWouldChangeItIsAlwaysAnswered(t *testing.T) {
	t.Run("nothing recorded about coverage", func(t *testing.T) {
		in := baseInputs()
		in.Coverage = nil
		in.Registry = nil
		got := explain.Explain(in).WhatWouldChangeIt
		if strings.TrimSpace(got) == "" {
			t.Fatal("unanswered when no coverage was recorded")
		}
		if !strings.Contains(got, "itself unknown") {
			t.Errorf("does not say the answer is unknown: %q", got)
		}
	})

	t.Run("an available next step is named", func(t *testing.T) {
		// baseInputs carries a Coverage and no Registry, which is how the
		// sixth question went unexercised: nextEvidence returned "" on the nil
		// registry and every existing test saw an empty string it did not
		// assert on.
		in := baseInputs()
		in.Registry = capability.DefaultRegistry()
		got := explain.Explain(in).WhatWouldChangeIt
		if !strings.Contains(got, "cheapest") {
			t.Errorf("does not name a next step: %q", got)
		}
	})

	t.Run("nothing available says so", func(t *testing.T) {
		// A registry providing only the cheap capabilities, all of them already
		// answered here — so every remaining gap is one nothing can fill.
		in := baseInputs()
		reg := capability.NewRegistry()
		reg.Register(cheapOnly{})
		in.Registry = reg
		in.Coverage = capability.NewCoverage(reg)
		for _, c := range []capability.AnalysisCapability{
			capability.LexicalContext, capability.ConstantEvaluation, capability.Taint,
		} {
			in.Coverage.Record(subject(), c, capability.Positive)
		}
		got := explain.Explain(in).WhatWouldChangeIt
		if strings.TrimSpace(got) == "" {
			t.Fatal("unanswered when nothing on this installation could help")
		}
		if !strings.Contains(got, "not a clearance") {
			t.Errorf("does not warn against reading the limit as a clearance: %q", got)
		}
	})
}

// Remediation and "what would change this" are separate fields, and the first
// no longer carries the second.
func TestRemediationDoesNotCarryTheSixthQuestion(t *testing.T) {
	in := baseInputs()
	in.Registry = capability.DefaultRegistry()
	e := explain.Explain(in)
	if strings.Contains(e.WhatToDo, "cheapest thing that would move") {
		t.Errorf("the remediation still has the sixth question glued to it: %q", e.WhatToDo)
	}
	if e.WhatWouldChangeIt == "" {
		t.Error("the sixth question was removed from remediation and not answered anywhere")
	}
}

// It never reads as a clearance, whichever branch answers it.
func TestNoAnswerReadsAsAClearance(t *testing.T) {
	in := baseInputs()
	in.Registry = capability.DefaultRegistry()
	for _, banned := range []string{"safe", "no risk", "not vulnerable", "nothing to worry"} {
		if strings.Contains(strings.ToLower(explain.Explain(in).WhatWouldChangeIt), banned) {
			t.Errorf("the answer contains %q", banned)
		}
	}
}
