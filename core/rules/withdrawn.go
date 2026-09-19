package rules

// WithdrawnRule is a tombstone for a rule whose CONDITION was retracted:
// nothing reports it any more, and nothing should.
//
// That is a different act from retirement, and the two must not be confused.
// RetiredRule covers "this condition is still real, another ID reports it now",
// and keeps waivers resolving by attaching the retired identity to the
// survivor's findings. It needs a survivor. When the conclusion is that the
// condition should never have been reported at all there is no survivor to
// retire into, so the rule leaves the set entirely.
//
// Deleting it silently is the trap RetiredRule's own documentation describes:
// baselines hash the rule ID into a fingerprint, and VEX statements and
// `nox:ignore` comments name it directly. An operator who waived AI-029 gets no
// finding and no explanation — and the unused-waiver sweep tells them the
// finding "may have been fixed" and to "check the rule ID", which is wrong on
// both counts.
//
// A tombstone costs one line per rule and turns that silence into a sentence.
// It carries no pattern and can never match anything; it exists so the scanner
// can say WHY a waiver stopped applying.
type WithdrawnRule struct {
	// ID is the withdrawn rule's identifier, e.g. "AI-029".
	ID string
	// Version is the release that withdrew it, so an operator can see whether
	// the change is older or newer than the waiver they are reading.
	Version string
	// Reason states what was wrong with the rule's claim, in a sentence an
	// operator can act on or argue with. "Removed" is not a reason.
	Reason string
}

// withdrawnRules is the tombstone registry.
//
// Entries are permanent. Removing one re-creates exactly the silence the
// registry exists to prevent, and costs a line of text to avoid.
var withdrawnRules = map[string]WithdrawnRule{
	"AI-029": {
		ID:      "AI-029",
		Version: "v1.36.0",
		Reason: "reported `presence_penalty=0` / `frequency_penalty=0` as \"repetition penalties " +
			"disabled\". 0.0 is the OpenAI API's own default, and the rule's remediation advised " +
			"setting them to \"(-2 to 0)\" -- a range containing the value it flagged. Repetitive " +
			"output is an output-quality property: no confidentiality, integrity or availability " +
			"claim follows from it, and CWE-754 describes neither.",
	},
	"AI-041": {
		ID:      "AI-041",
		Version: "v1.36.0",
		Reason: "reported temperature/top_p above 0.9 as \"high temperature/top_p settings\". Its own " +
			"remediation described the concern as determinism (\"use 0.1-0.3 for deterministic " +
			"outputs\"), which is a tuning property rather than a security one. Measured on crewAI, " +
			"every one of its findings was `top_p=0.9`, an ordinary nucleus-sampling value.",
	},
	"AI-022": {
		ID:      "AI-022",
		Version: "v1.38.0",
		Reason: "reported temperature 0.8-1.0 at High severity as \"allowing hallucination\". AI-041 was " +
			"withdrawn in v1.36.0 for flagging temperature above 0.9 as a tuning property rather than a " +
			"security one, and this rule flagged a strict superset of those values. 1.0 is the default " +
			"of both the OpenAI and Anthropic APIs, and the documented default for o1/o3 reasoning " +
			"models, so the rule reported the vendor default as a High finding.",
	},
	"AI-023": {
		ID:      "AI-023",
		Version: "v1.38.0",
		Reason: "reported top_p below 0.7 as \"reducing output diversity\", and its remediation gave the " +
			"cost as \"reduce response quality\". Output diversity is an output-quality property: no " +
			"confidentiality, integrity or availability claim follows from it, and CWE-754 describes " +
			"none of it. Its recommended band also contradicted AI-041 while both shipped.",
	},
	"AI-028": {
		ID:      "AI-028",
		Version: "v1.38.0",
		Reason: "reported an unset seed as \"causing non-deterministic output\", for \"reproducible " +
			"outputs in testing and auditing\". Determinism is the tuning property AI-041 was withdrawn " +
			"for in v1.36.0, and the OpenAI API's `seed` is optional and unset by default.",
	},
	"AI-037": {
		ID:      "AI-037",
		Version: "v1.38.0",
		Reason: "reported system prompts over 2000 characters as able to \"cause inconsistent model " +
			"behavior and higher latency\". Consistency and latency are quality and performance " +
			"properties; the rule stated no confidentiality, integrity or availability claim.",
	},
}

// Withdrawn returns the tombstone for a rule ID, if it has one.
func Withdrawn(id string) (WithdrawnRule, bool) {
	w, ok := withdrawnRules[id]
	return w, ok
}

// WithdrawnIDs returns every withdrawn rule ID. Order is unspecified.
func WithdrawnIDs() []string {
	out := make([]string, 0, len(withdrawnRules))
	for id := range withdrawnRules {
		out = append(out, id)
	}
	return out
}
