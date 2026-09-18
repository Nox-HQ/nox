package rules

import "strconv"

// Contradiction records a remediation that recommends the value its own rule
// flags — a proposition that did not survive being written down twice.
//
// AI-029 is the measured case and the reason this file exists. It flagged
// `presence_penalty = 0` as "LLM repetition penalties disabled", and its own
// remediation read:
//
//	Set presence_penalty (-2 to 0) and frequency_penalty (-2 to 0) to reduce
//	repetitive token generation.
//
// The recommended range CONTAINS the flagged value. Following the remediation
// to the letter can leave the finding in place, which means the rule was not
// describing a condition an operator could act on. It fired 446 times on the
// pinned corpus before anyone read the two strings next to each other.
//
// This is deliberately NOT part of CheckCoherence. Coherence refuses: a rule
// whose declared semantics its evaluation path cannot consume is broken and
// must not reach a rule set. A contradictory remediation is a SMELL. It says
// "a human should read this rule's proposition", and a human may well conclude
// the rule is fine and the wording is loose. Refusing it would make a
// judgement this analysis is not entitled to make — see
// docs/design/rule-review-candidates.md.
//
// # What is detected, and what is deliberately not
//
// Only the narrow, checkable form: the pattern pins a NAMED PARAMETER to a
// LITERAL VALUE, and the remediation, discussing that same parameter, endorses
// a numeric range that contains it.
//
// The obvious wider definition — "the rule's own pattern matches its own
// remediation text" — was implemented first and measured on the built-in
// catalogue. It reported 35 rules, of which essentially all were correct
// remediations quoting the defect in order to say remove it:
//
//	IAC-202  Replace failed_when: false with specific failure conditions.
//	IAC-203  Enable certificate validation by removing validate_certs: false.
//
// and it did not report AI-029 at all, because AI-029's pattern requires an
// `=` between the parameter and the value and its prose has none. Wrong on
// both ends, so it is not what ships. See TestSelfMatchIsNotTheSignal.
type Contradiction struct {
	// Param is the parameter named by both the trigger and the remediation.
	Param string
	// Flagged is the literal value the pattern requires in order to fire.
	Flagged string
	// Low and High are the inclusive bounds of the range the remediation
	// endorses for Param.
	Low, High float64
	// Endorsement is the remediation substring the range was read from, so a
	// maintainer can judge the reading without re-deriving it.
	Endorsement string
}

// RemediationContradiction reports whether the rule's remediation endorses a
// value range containing the literal value its pattern requires.
//
// The second result is false for the overwhelming majority of rules: a rule
// whose pattern pins no literal, or whose remediation names no range for the
// pinned parameter, cannot contradict itself in this sense and is not evidence
// of anything.
func (r *Rule) RemediationContradiction() (Contradiction, bool) {
	if r.Pattern == "" || r.Remediation == "" {
		return Contradiction{}, false
	}
	params, value, ok := flaggedAssignment(r.Pattern)
	if !ok {
		return Contradiction{}, false
	}
	flagged, err := strconv.ParseFloat(value, 64)
	if err != nil {
		// A non-numeric pin (`false`, `LoadBalancer`) has no range to fall
		// inside. Endorsement of a literal was measured too and is the same
		// false-positive flood as self-matching, for the same reason: prose
		// naming the bad value in order to reject it.
		return Contradiction{}, false
	}
	for _, p := range params {
		for _, e := range endorsedRanges(r.Remediation, p) {
			if flagged >= e.low && flagged <= e.high {
				return Contradiction{
					Param:       p,
					Flagged:     value,
					Low:         e.low,
					High:        e.high,
					Endorsement: e.text,
				}, true
			}
		}
	}
	return Contradiction{}, false
}

// PinnedAssignment reports the parameter names and literal value the rule's
// pattern requires in order to fire, when it pins one.
//
// It exists so a caller can tell "this rule has nothing for the contradiction
// analysis to read" apart from "this rule was analysed and is clean". A gate
// asserting zero contradictions needs that distinction: without it, a scanner
// that quietly stopped parsing patterns would keep the gate green forever.
//
// ok is false for the overwhelming majority of rules — a pattern that pins a
// range rather than a literal, or names no parameter, has nothing to compare.
func (r *Rule) PinnedAssignment() (params []string, value string, ok bool) {
	if r.Pattern == "" {
		return nil, "", false
	}
	return flaggedAssignment(r.Pattern)
}
