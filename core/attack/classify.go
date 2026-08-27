package attack

import (
	"fmt"
	"math"
	"strings"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
)

// Classification is the standards mapping and score for one attack trace.
//
// It exists because a standards label alone is a commodity: any static scanner
// can print "ASI01, CVSS 9.3" off a rule. What nox knows and a static scanner
// does not is whether the attack actually worked, and the score has to say so.
// A CONFIRMED exploit and an untested hypothesis carrying the same number is
// precisely how a scanner teaches its users to stop reading its output.
type Classification struct {
	OWASPASI string `json:"owasp_asi,omitempty"`
	OWASPLLM string `json:"owasp_llm,omitempty"`
	CWE      string `json:"cwe,omitempty"`
	// CVSSVector is the CVSS v4.0 base vector for a CONFIRMED exploit of this
	// scenario. nox publishes the vector and does NOT publish a CVSS score:
	// see impactWeight for why. Score it with a v4.0 calculator if you need
	// the number; the vector is the checkable artifact and the one tools
	// actually consume.
	CVSSVector string `json:"cvss_vector,omitempty"`
	// ImpactWeight is derived from the vector's own impact metrics. It is nox's
	// input to Score, not a CVSS score, and is never presented as one.
	ImpactWeight float64 `json:"impact_weight"`
	// Score is nox's exploitability-weighted severity, 0-10. It is NOT CVSS.
	// CVSS scores a vulnerability class; this scores what nox actually
	// demonstrated about THIS system, which is the whole point of running the
	// attack rather than reading the rule.
	Score float64 `json:"score"`
	// Severity is the nox severity band for Score.
	Severity string `json:"severity"`
	// Rationale explains the adjustment in one sentence, so a reader can see
	// why a score moved rather than having to trust it.
	Rationale string `json:"rationale"`
}

// Demonstration factors scale a scenario's impact weight by what the run actually
// established. The gaps matter more than the absolute values, and the ordering
// is the contract the tests pin:
//
//	CONFIRMED > INCONCLUSIVE > PLAUSIBLE > PREVENTED > POTENTIAL
//
// PREVENTED sits low but never at zero, and POTENTIAL is the floor of the
// ladder rather than an absence of risk.
const (
	// factorConfirmed — the invariant was observed being violated and the
	// violation reproduced on every replay. Nothing is deducted: this is the
	// one state where the weight describes something that happened.
	factorConfirmed = 1.00
	// factorConfirmedPartial — the exploit was observed but only reproduced on
	// some replays. It is still a demonstrated exploit, so the deduction is
	// deliberately small; a flaky exploit is a real exploit with a worse
	// success rate, not a lesser class of finding.
	factorConfirmedPartial = 0.95
	// factorInconclusive — execution happened and told us nothing decisive
	// (budget exhausted, target errored, oracle unavailable). Reduced because
	// the claim is unproven, but held above an untested hypothesis because at
	// least the attempt was made.
	factorInconclusive = 0.55
	// factorPlausible — a credible attack path was constructed and never
	// fired. A hypothesis is not a vulnerability, and scoring one as if it were
	// is how scanners lose the reader's trust for every finding that follows.
	factorPlausible = 0.50
	// factorPrevented — a defense was observed stopping the attempt. This is
	// the floor for an executed scenario, NOT zero: the weakness is still
	// present in the system and the defense held only against the strategies
	// nox tested. Dropping to zero here would encode "defended" as "fixed".
	factorPrevented = 0.35
	// factorPotential — static evidence only; no path constructed, nothing
	// executed. The lowest band nox will assign.
	factorPotential = 0.25
)

// unknownImpactWeight is used when a scenario carries no parseable vector.
//
// It is deliberately mid-scale rather than 0.0. core/analyzers/deps takes the
// same position for advisories whose severity cannot be computed: an unknown
// score must read as "unknown", and 0.0 reads as "harmless" — the one meaning
// nox has no evidence for.
const unknownImpactWeight = 5.0

// nox deliberately does NOT compute or record CVSS v4.0 scores.
//
// v4.0 scoring is not a formula over the vector: it clusters ~15 million
// vectors into 270 MacroVectors, looks the MacroVector up in an expert-ranked
// table, then interpolates by severity distance to neighbouring MacroVectors.
// Reimplementing that here would give nox a second severity authority that can
// silently disagree with the v3.1 scorer in core/analyzers/deps — which already
// documents that it does not attempt v4 for exactly this reason.
//
// The alternative that was tried and rejected was a small table of hand-typed
// base scores. Two of the three were wrong. A security tool asserting a
// standards-branded number nobody computed is the same defect class as a
// regression suite reporting "fix holds" for a target it never reached: a
// confident claim with nothing behind it.
//
// So nox publishes the VECTOR, which is factual and checkable, and scores with
// its own weight derived from the vector's own impact metrics. That number is
// labelled as nox's, never as CVSS.

// impactWeight derives a 0-10 weight from a CVSS v4.0 base vector's own
// metrics. It is a transparent function of the vector — no lookup table, no
// external authority — so a reader can verify it by reading the code, and it
// cannot drift out of sync with a published table it does not use.
//
// Exploitability metrics (AV/AC/AT/PR/UI) scale how reachable the weakness is;
// impact metrics (VC/VI/VA and their subsequent-system counterparts) scale what
// it costs. A vector nox cannot parse yields unknownImpactWeight rather than
// zero, because "unknown" and "harmless" are different claims and only one of
// them is safe to make by default.
func impactWeight(vector string) (weight float64, ok bool) {
	m, ok := parseCVSSv4Base(vector)
	if !ok {
		return unknownImpactWeight, false
	}

	// Reachability: the product of how little the attacker needs. Each factor
	// is a discount, not a veto — a harder precondition makes an exploit less
	// likely to be reached, it does not make it benign.
	reach := 1.0
	reach *= map[string]float64{"N": 1.00, "A": 0.90, "L": 0.70, "P": 0.50}[m["AV"]]
	reach *= map[string]float64{"L": 1.00, "H": 0.90}[m["AC"]]
	reach *= map[string]float64{"N": 1.00, "P": 0.92}[m["AT"]]
	reach *= map[string]float64{"N": 1.00, "L": 0.80, "H": 0.62}[m["PR"]]
	reach *= map[string]float64{"N": 1.00, "P": 0.88, "A": 0.76}[m["UI"]]

	// Consequence. The dominant term is the WORST impact on the vulnerable
	// system, because one total compromise is the story regardless of how many
	// other dimensions also fell. Breadth adds a little on top so three Highs
	// outrank one, and subsequent-system impact adds again because a weakness
	// that escapes its own blast radius is worse than one that does not.
	//
	// Subsequent impact is additive rather than a share of the total: making it
	// a share would cap every vulnerability with no downstream reach below the
	// top band, and "network-reachable, unauthenticated, full compromise, and
	// demonstrated" is exactly what the top band is for.
	sev := map[string]float64{"H": 1.00, "L": 0.50, "N": 0.00}
	vuln := math.Max(sev[m["VC"]], math.Max(sev[m["VI"]], sev[m["VA"]]))
	breadth := (sev[m["VC"]] + sev[m["VI"]] + sev[m["VA"]]) / 3.0
	subsequent := math.Max(sev[m["SC"]], math.Max(sev[m["SI"]], sev[m["SA"]]))

	consequence := math.Min(1.0, 0.85*vuln+0.15*breadth+0.15*subsequent)
	return roundScore(10.0 * reach * consequence), true
}

// cvssV4BaseMetrics are the mandatory CVSS v4.0 base metrics and their legal
// values. A vector missing any of them, or carrying a value outside the set, is
// not a base vector and must not be scored — a typo that silently scored would
// attach a real-looking number to a metric nobody wrote.
var cvssV4BaseMetrics = map[string][]string{
	"AV": {"N", "A", "L", "P"},
	"AC": {"L", "H"},
	"AT": {"N", "P"},
	"PR": {"N", "L", "H"},
	"UI": {"N", "P", "A"},
	"VC": {"H", "L", "N"},
	"VI": {"H", "L", "N"},
	"VA": {"H", "L", "N"},
	"SC": {"H", "L", "N"},
	"SI": {"H", "L", "N"},
	"SA": {"H", "L", "N"},
}

// parseCVSSv4Base validates a CVSS v4.0 vector and returns its base metrics.
// Threat, environmental, and supplemental metrics may follow the base ones and
// are ignored: they are not part of a base score.
//
// This is a validator, not a scorer. See impactWeight for why nox does not
// compute a v4 score.
func parseCVSSv4Base(vector string) (map[string]string, bool) {
	const prefix = "CVSS:4.0/"
	if !strings.HasPrefix(vector, prefix) {
		return nil, false
	}
	got := make(map[string]string, len(cvssV4BaseMetrics))
	for _, part := range strings.Split(strings.TrimPrefix(vector, prefix), "/") {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			return nil, false
		}
		allowed, mandatory := cvssV4BaseMetrics[k]
		if !mandatory {
			continue
		}
		if _, dup := got[k]; dup {
			return nil, false
		}
		if !containsString(allowed, v) {
			return nil, false
		}
		got[k] = v
	}
	if len(got) != len(cvssV4BaseMetrics) {
		return nil, false
	}
	return got, true
}

// containsString reports whether v is in vals.
func containsString(vals []string, v string) bool {
	for _, s := range vals {
		if s == v {
			return true
		}
	}
	return false
}

// ImpactWeight returns nox's 0-10 weight for a CVSS v4.0 base vector, derived
// from the vector's own metrics.
//
// It is NOT a CVSS score and must never be labelled as one: nox does not
// implement v4.0 scoring, and a number that carries a standard's name has to
// come from that standard's algorithm. The bool reports whether the vector
// parsed; a false means the returned weight is the "unknown" default, which
// callers must distinguish from a genuinely low weight.
func ImpactWeight(vector string) (float64, bool) { return impactWeight(vector) }

// Classify maps a scenario and a demonstrated exploitability onto a
// Classification.
//
// reproducedHits and samples are the determinism-gate tally; they only affect
// the score for a CONFIRMED trace, where they separate an exploit that fired
// every time from one that fired sometimes.
func Classify(s Scenario, e evidence.Exploitability, reproducedHits, samples int) Classification {
	c := Classification{
		OWASPASI:   s.OWASPASI,
		OWASPLLM:   s.OWASPLLM,
		CWE:        s.CWE,
		CVSSVector: s.CVSSVector,
	}

	base, scored := impactWeight(s.CVSSVector)
	if !scored {
		base = unknownImpactWeight
	}
	c.ImpactWeight = base

	factor, rationale := demonstrationFactor(e, reproducedHits, samples)
	if !scored {
		rationale += ", from an unknown impact weight because the scenario carries no parseable CVSS v4.0 base vector"
	}
	c.Score = roundScore(base * factor)
	c.Severity = string(severityForScore(c.Score))
	c.Rationale = rationale
	return c
}

// demonstrationFactor returns the multiplier for what the run established and
// the one-sentence rationale that goes with it. The rationale is part of the
// contract, not decoration: a score that moved without saying why is a score
// the reader has to take on faith.
//
// No rationale asserts that anything is protected. nox reports what it
// observed; "not exploited under the strategies tested" is an observation,
// "not exploitable" is a claim nox has no way to establish.
func demonstrationFactor(e evidence.Exploitability, reproducedHits, samples int) (factor float64, rationale string) {
	switch e {
	case evidence.Confirmed:
		if samples > 0 && reproducedHits > 0 && reproducedHits < samples {
			return factorConfirmedPartial, fmt.Sprintf(
				"an oracle observed the invariant violated but it reproduced only %d of %d times, so the score is trimmed just below a fully reproduced exploit",
				reproducedHits, samples)
		}
		return factorConfirmed, "an oracle observed the invariant actually being violated and it reproduced on every sample, so the full impact weight stands"
	case evidence.Inconclusive:
		return factorInconclusive, "the attack executed but the evidence was insufficient to decide either way, so the score is reduced for missing evidence — not for an absence of the weakness"
	case evidence.Plausible:
		return factorPlausible, "a credible attack path was constructed but never executed, so the score is materially reduced: a hypothesis is not a demonstrated vulnerability"
	case evidence.Prevented:
		return factorPrevented, "a defense was observed stopping the attempt under the strategies tested, so the score falls to the floor rather than to zero — the weakness is still present, only currently defended"
	case evidence.Potential:
		return factorPotential, "only static evidence supports this: no attack path was constructed and nothing was executed, so the score sits in the lowest band"
	default:
		return factorPotential, fmt.Sprintf("exploitability state %q is unrecognised, so the score is held in the lowest band rather than assumed", string(e))
	}
}

// severityForScore buckets a score with the standard CVSS qualitative rating
// scale, expressed in nox's own severity vocabulary. The bands are the same
// ones core/analyzers/deps applies to dependency advisories, so one number
// means one thing wherever it is printed.
func severityForScore(score float64) findings.Severity {
	switch {
	case score >= 9.0:
		return findings.SeverityCritical
	case score >= 7.0:
		return findings.SeverityHigh
	case score >= 4.0:
		return findings.SeverityMedium
	case score >= 0.1:
		return findings.SeverityLow
	default:
		return findings.SeverityInfo
	}
}

// roundScore rounds to one decimal place, the precision CVSS scores are
// published at. Rounding here rather than at print time keeps the stored score
// and the severity band derived from it consistent.
func roundScore(f float64) float64 {
	return math.Round(f*10) / 10
}

// classified returns t with its Classification filled in from its scenario and
// the exploitability just derived for it. Every point that finalises a verdict
// returns through here, so a trace cannot be emitted carrying a verdict but no
// mapping — including the traces that never ran, where "PLAUSIBLE, discounted"
// is itself the honest answer.
func classified(t Trace) Trace {
	scen, _ := ScenarioByID(t.ScenarioID)
	t.Classification = Classify(scen, t.Exploitability, t.ReproductionHits, t.ReproductionSamples)
	return t
}
