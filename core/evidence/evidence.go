// Package evidence answers one question — "why does nox believe this, and how
// strongly?" — and enforces that a weak claim can never masquerade as a strong
// one. A single LLM judgment must not read like a reproduced exploit; one
// project scanning itself a hundred times must not read like a hundred
// independent corroborations.
//
// Its consumer today is dynamic exploit validation (core/attack). It is
// deliberately a standalone model rather than part of that package, because the
// same rules have to hold for anything else that ever produces an
// evidence-backed verdict — notably a vulnerability-intelligence service, which
// nox does not ship in the CLI (see docs/design/intelligence-service.md). One
// definition of CONFIRMED, in one place, is the only way those surfaces cannot
// drift apart on the thing that makes their output trustworthy.
//
// The package is pure: no I/O, no network, no clock. Timestamps are supplied by
// callers so that every derived verdict is reproducible from its inputs.
package evidence

import (
	"sort"
)

// Exploitability is a finding's dynamic-validation lifecycle state. It is
// deliberately independent of severity: a CRITICAL finding may be PREVENTED and
// a MEDIUM one CONFIRMED.
type Exploitability string

// Exploitability states.
const (
	// Potential — static evidence suggests a vulnerability. The default for
	// every finding a scan produces; no attack path has been constructed.
	Potential Exploitability = "POTENTIAL"
	// Plausible — nox constructed a credible attack path (an exploit hypothesis
	// grounded in reachable capabilities), but has not executed anything.
	Plausible Exploitability = "PLAUSIBLE"
	// Prevented — nox attempted exploitation and observed a defense stopping the
	// invariant violation. NOT a proof of safety: it means "not exploited under
	// the strategies tested".
	Prevented Exploitability = "PREVENTED"
	// Inconclusive — execution occurred but the evidence was insufficient to
	// decide either way (budget exhausted, target errored, oracle unavailable).
	Inconclusive Exploitability = "INCONCLUSIVE"
	// Confirmed — nox observed the security invariant actually being violated.
	Confirmed Exploitability = "CONFIRMED"
)

// Valid reports whether e is a defined state.
func (e Exploitability) Valid() bool {
	switch e {
	case Potential, Plausible, Prevented, Inconclusive, Confirmed:
		return true
	}
	return false
}

// rank orders states by how much they have been established. Prevented and
// Inconclusive both sit above Plausible (execution happened) and below
// Confirmed; Prevented outranks Inconclusive because it carries a real
// observation rather than an absence of one.
func (e Exploitability) rank() int {
	switch e {
	case Potential:
		return 1
	case Plausible:
		return 2
	case Inconclusive:
		return 3
	case Prevented:
		return 4
	case Confirmed:
		return 5
	default:
		return 0
	}
}

// AtLeast reports whether e is at or above other on the establishment ladder.
func (e Exploitability) AtLeast(other Exploitability) bool {
	return e.rank() >= other.rank()
}

// Kind classifies how a claim was established. The set is shared by both
// capabilities so a runtime exploit and a research conclusion are weighed on
// one scale rather than two incomparable ones.
type Kind string

// Evidence kinds, weakest to strongest.
const (
	// KindHeuristic — a pattern matched. The weakest claim nox makes.
	KindHeuristic Kind = "heuristic"
	// KindSemantic — an LLM judged it so. Never deterministic, always labeled;
	// used only where machine-verifiable evidence is impossible.
	KindSemantic Kind = "semantic"
	// KindStatic — deterministic static analysis established it (a taint path,
	// a resolved version range).
	KindStatic Kind = "static"
	// KindIndependentObservation — a distinct source reported the same thing.
	KindIndependentObservation Kind = "independent_observation"
	// KindResearchHypothesis — a research agent's reasoned claim, backed by
	// cited artifacts but not itself reproduced.
	KindResearchHypothesis Kind = "research_hypothesis"
	// KindSourceConfirmed — the vulnerable code path was read and confirmed.
	KindSourceConfirmed Kind = "source_confirmed"
	// KindControlledReproduction — reproduced in a controlled environment.
	KindControlledReproduction Kind = "controlled_reproduction"
	// KindDynamicExploit — a deterministic runtime oracle observed a security
	// invariant being violated. The strongest claim nox can produce on its own.
	KindDynamicExploit Kind = "dynamic_exploit"
	// KindMaintainerConfirmed — the upstream maintainer confirmed it.
	KindMaintainerConfirmed Kind = "maintainer_confirmed"
	// KindPublicAdvisory — a published advisory (OSV/CVE/GHSA) asserts it.
	KindPublicAdvisory Kind = "public_advisory"
)

// strengths maps each kind to a 0-100 weight. The gaps matter more than the
// absolute numbers: a semantic judgment sits below any deterministic claim, and
// nothing short of reproduction, a maintainer, or an advisory reaches the top
// band.
var strengths = map[Kind]int{
	KindHeuristic:              10,
	KindSemantic:               20,
	KindStatic:                 40,
	KindIndependentObservation: 45,
	KindResearchHypothesis:     50,
	KindSourceConfirmed:        70,
	KindControlledReproduction: 85,
	KindDynamicExploit:         95,
	KindMaintainerConfirmed:    95,
	KindPublicAdvisory:         100,
}

// Strength returns the 0-100 weight of the kind; an unknown kind weighs 0 so an
// unrecognised claim can never inflate a verdict.
func (k Kind) Strength() int { return strengths[k] }

// Valid reports whether k is a defined evidence kind.
func (k Kind) Valid() bool { _, ok := strengths[k]; return ok }

// Deterministic reports whether the kind was established by a machine-checkable
// oracle rather than by judgment. Only deterministic claims may, on their own,
// carry a ledger to ConfidenceConfirmed.
func (k Kind) Deterministic() bool {
	switch k {
	case KindStatic, KindSourceConfirmed, KindControlledReproduction,
		KindDynamicExploit, KindMaintainerConfirmed, KindPublicAdvisory:
		return true
	}
	return false
}

// Semantic reports whether the kind is an LLM judgment. Callers must surface
// this to users: §14 of the exploit-validation PRD requires semantic verdicts
// to be explicitly identified as such.
func (k Kind) Semantic() bool { return k == KindSemantic }

// Confidence is the aggregate certainty of a ledger of claims.
type Confidence string

// Confidence levels.
const (
	ConfidenceLow       Confidence = "LOW"
	ConfidenceMedium    Confidence = "MEDIUM"
	ConfidenceHigh      Confidence = "HIGH"
	ConfidenceConfirmed Confidence = "CONFIRMED"
)

// rank orders confidence levels.
func (c Confidence) rank() int {
	switch c {
	case ConfidenceLow:
		return 1
	case ConfidenceMedium:
		return 2
	case ConfidenceHigh:
		return 3
	case ConfidenceConfirmed:
		return 4
	default:
		return 0
	}
}

// AtLeast reports whether c is at or above other.
func (c Confidence) AtLeast(other Confidence) bool { return c.rank() >= other.rank() }

// Provenance records where a claim came from. SourceID is an opaque, stable
// identifier for the *reporter* — never a hostname, repository name, or path.
// It exists so aggregation can count distinct sources without learning who they
// are.
type Provenance struct {
	// Source names the producing subsystem: "nox-scan", "nox-attack",
	// "nox-intel", "osv", "researcher", "maintainer".
	Source string `json:"source"`
	// SourceID is an opaque per-reporter identifier used ONLY for independence
	// counting. Empty means "unattributed" and never counts as independent.
	SourceID string `json:"source_id,omitempty"`
	// Tool and Version identify the producer build, so a claim can be traced to
	// the code that made it.
	Tool    string `json:"tool,omitempty"`
	Version string `json:"version,omitempty"`
	// ObservedAt is an RFC3339 timestamp supplied by the caller. The package
	// never reads a clock, so verdicts stay reproducible.
	ObservedAt string `json:"observed_at,omitempty"`
	// Reference is a citation for the claim: an advisory ID, a commit, a trace
	// ID. It is what makes the claim checkable by a human.
	Reference string `json:"reference,omitempty"`
}

// Claim is one evidence-bearing statement about a vulnerability or exploit.
type Claim struct {
	Kind       Kind              `json:"kind"`
	Statement  string            `json:"statement"`
	Provenance Provenance        `json:"provenance"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Ledger is an ordered set of claims about one subject, and the rules for
// turning them into a confidence level and an exploitability state.
//
// The zero Ledger is usable.
type Ledger struct {
	Claims []Claim `json:"claims"`
}

// Add appends a claim. Claims with an unrecognised kind are kept (so nothing is
// silently dropped from the audit trail) but contribute zero strength.
func (l *Ledger) Add(c Claim) { l.Claims = append(l.Claims, c) }

// Len returns the number of claims.
func (l *Ledger) Len() int { return len(l.Claims) }

// Kinds returns the distinct evidence kinds present, sorted for determinism.
func (l *Ledger) Kinds() []Kind {
	seen := make(map[Kind]bool, len(l.Claims))
	for _, c := range l.Claims {
		seen[c.Kind] = true
	}
	out := make([]Kind, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}

// Strongest returns the highest-strength claim and true, or the zero Claim and
// false for an empty ledger. Ties break on the earlier claim, so the result is
// stable under re-evaluation.
func (l *Ledger) Strongest() (Claim, bool) {
	best := -1
	for i := range l.Claims {
		if best < 0 || l.Claims[i].Kind.Strength() > l.Claims[best].Kind.Strength() {
			best = i
		}
	}
	if best < 0 {
		return Claim{}, false
	}
	return l.Claims[best], true
}

// HasDeterministic reports whether any claim was machine-established.
func (l *Ledger) HasDeterministic() bool {
	for _, c := range l.Claims {
		if c.Kind.Deterministic() {
			return true
		}
	}
	return false
}

// HasSemantic reports whether any claim is an LLM judgment. Consumers use this
// to label a verdict as partly semantic.
func (l *Ledger) HasSemantic() bool {
	for _, c := range l.Claims {
		if c.Kind.Semantic() {
			return true
		}
	}
	return false
}

// IndependentSources counts distinct non-empty Provenance.SourceID values.
//
// This is the guard against the failure mode in §11 of the intelligence PRD:
// one project scanning itself a hundred times produces a hundred observations
// but exactly ONE independent source. Unattributed claims (empty SourceID)
// never count, because an unattributed claim cannot be shown to be independent
// of any other.
func (l *Ledger) IndependentSources() int {
	seen := make(map[string]bool, len(l.Claims))
	for _, c := range l.Claims {
		if c.Provenance.SourceID != "" {
			seen[c.Provenance.SourceID] = true
		}
	}
	return len(seen)
}

// Confidence aggregates the ledger into a level.
//
// The rules, in order:
//
//  1. An empty ledger is LOW.
//  2. CONFIRMED requires a DETERMINISTIC claim of at least reproduction
//     strength (controlled reproduction, dynamic exploit, maintainer
//     confirmation, or a public advisory). No amount of heuristics, judgments,
//     or repeated observation reaches it — §24: "No single agent conclusion
//     should independently elevate a candidate to CONFIRMED."
//  3. Otherwise the level follows the strongest claim, with one promotion: two
//     or more INDEPENDENT sources lift the result one level, capped at HIGH.
//     Corroboration strengthens belief; it never substitutes for proof.
//  4. A ledger whose only claims are semantic is capped at MEDIUM, however many
//     judgments it holds — restating an opinion is not evidence.
func (l *Ledger) Confidence() Confidence {
	if len(l.Claims) == 0 {
		return ConfidenceLow
	}

	for _, c := range l.Claims {
		if c.Kind.Deterministic() && c.Kind.Strength() >= strengths[KindControlledReproduction] {
			return ConfidenceConfirmed
		}
	}

	strongest, _ := l.Strongest()
	level := levelForStrength(strongest.Kind.Strength())

	if l.IndependentSources() >= 2 && level.rank() < ConfidenceHigh.rank() {
		level = promote(level)
	}

	if onlySemantic(l.Claims) && level.AtLeast(ConfidenceHigh) {
		level = ConfidenceMedium
	}
	return level
}

// levelForStrength maps a 0-100 strength onto a confidence band. The bands stop
// short of CONFIRMED: reaching that requires the deterministic gate in
// Ledger.Confidence, not a high score.
func levelForStrength(s int) Confidence {
	switch {
	case s >= 70:
		return ConfidenceHigh
	case s >= 40:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// promote lifts a level by one, capped at HIGH.
func promote(c Confidence) Confidence {
	switch c {
	case ConfidenceLow:
		return ConfidenceMedium
	case ConfidenceMedium, ConfidenceHigh:
		return ConfidenceHigh
	default:
		return c
	}
}

// onlySemantic reports whether every claim is an LLM judgment.
func onlySemantic(claims []Claim) bool {
	for _, c := range claims {
		if !c.Kind.Semantic() {
			return false
		}
	}
	return len(claims) > 0
}
