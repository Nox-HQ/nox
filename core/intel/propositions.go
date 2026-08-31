package intel

import (
	"sort"

	"github.com/nox-hq/nox-core/evidence"
)

// ResearchProposition is a structured claim an intelligence source makes about
// a package, ahead of or alongside a published advisory.
//
// Milestone M's shape: intel should be able to say more than "CVE-X affects
// package@version". It can carry the affected symbol, a trigger condition, an
// affected configuration, known entry points, a proof-of-concept hypothesis, an
// oracle, reproduction evidence, known refutations and maintainer evidence.
//
// # The invariant this type exists to hold
//
// Intel provides evidence. It does not decide what affects a repository.
//
// Every proposition here is about a PACKAGE — a thing that exists in the world,
// independent of anyone's code. Whether it applies to a particular repository is
// a different proposition, about a candidate or a flow in that repository, and
// only local analysis can establish it. A researcher's confidence that a
// symbol is dangerous says nothing about whether this build calls it.
//
// core/reasoning already refuses to record an advisory as evidence about a
// candidate, for exactly this reason, and left the package side unbuilt. This
// is that side. The claims it produces are filed against the package subject
// and can never reach a candidate's ledger, because aggregation is per-subject
// and the two subjects differ.
type ResearchProposition struct {
	// Ecosystem and Package identify what this is about.
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	// Advisory is the identifier, when one exists. Empty for research that
	// precedes publication — which is the case M is really for, since an
	// unpublished finding is where intel could help before OSV can.
	Advisory string `json:"advisory,omitempty"`

	// AffectedSymbols are the import paths or symbols the research names.
	// Local nox tests whether the build references them; intel does not know.
	AffectedSymbols []string `json:"affected_symbols,omitempty"`
	// TriggerCondition is what the researcher believes must hold. Words, not
	// constraints: nox records no path constraints and neither does this.
	TriggerCondition string `json:"trigger_condition,omitempty"`
	// AffectedConfiguration narrows it to a configuration, when it applies only
	// under one.
	AffectedConfiguration string `json:"affected_configuration,omitempty"`
	// KnownEntryPoints are entry points the research observed reaching it.
	// Whether THIS application has them is a local question.
	KnownEntryPoints []string `json:"known_entry_points,omitempty"`
	// PoCHypothesis describes an attack the research believes would work.
	PoCHypothesis string `json:"poc_hypothesis,omitempty"`
	// Oracle names what would settle it.
	Oracle string `json:"oracle,omitempty"`

	// Maturity is how far the research got, and it is what stops a hypothesis
	// being read as a fact.
	Maturity Maturity `json:"maturity"`
	// Refutations are what argues against it — a maintainer disputing it, a
	// reproduction that did not hold. Carried because a source that only
	// forwards supporting evidence is a source that cannot be checked.
	Refutations []string `json:"refutations,omitempty"`
	// ReporterCount is the number of DISTINCT reporters, never observations.
	// One project scanning itself a thousand times is one source.
	ReporterCount int `json:"reporter_count,omitempty"`
	// Attested records whether any of it came from a source whose identity the
	// service could check. Anonymous intake is deliberate; treating anonymous
	// corroboration as attestation would not be.
	Attested bool `json:"attested,omitempty"`
}

// Maturity is the research ladder, weakest first.
//
// It exists so a zero-day can begin benefiting users before publication without
// pretending to a certainty it does not have. Each rung maps to an evidence
// kind, and the mapping is the whole safety property: a hypothesis cannot enter
// a local ledger at advisory strength however confident its author was.
type Maturity string

const (
	// MaturityHypothesis — a researcher believes there is something here.
	MaturityHypothesis Maturity = "research_hypothesis"
	// MaturityIndependent — distinct reporters have seen it.
	MaturityIndependent Maturity = "independent_observation"
	// MaturityStatic — static analysis established it against the package.
	MaturityStatic Maturity = "static_confirmation"
	// MaturityReproduced — a controlled reproduction held.
	MaturityReproduced Maturity = "controlled_reproduction"
	// MaturityMaintainer — the maintainer confirmed it.
	MaturityMaintainer Maturity = "maintainer_confirmed"
	// MaturityAdvisory — it is published.
	MaturityAdvisory Maturity = "public_advisory"
)

// kind maps a maturity rung to the evidence kind it may enter a ledger at.
//
// An unrecognised rung maps to KindHeuristic rather than to something in the
// middle: a maturity this build does not understand is not evidence of
// anything, and reading it generously is how a source's vocabulary becomes a
// consumer's verdict.
func (m Maturity) kind() evidence.Kind {
	switch m {
	case MaturityIndependent:
		return evidence.KindIndependentObservation
	case MaturityStatic:
		return evidence.KindStatic
	case MaturityReproduced:
		return evidence.KindControlledReproduction
	case MaturityMaintainer:
		return evidence.KindMaintainerConfirmed
	case MaturityAdvisory:
		return evidence.KindPublicAdvisory
	case MaturityHypothesis:
		return evidence.KindResearchHypothesis
	default:
		return evidence.KindHeuristic
	}
}

// PackageSubject is the subject a proposition about a package is filed against.
//
// Deliberately distinct from any candidate, flow or finding subject in the
// scanned repository. Aggregation is per-subject, so this is the mechanism that
// keeps a researcher's confidence about a library from becoming confidence
// about somebody's code.
func PackageSubject(ecosystem, pkg string) evidence.Subject {
	return evidence.Subject{Kind: evidence.SubjectPackage, ID: ecosystem + "/" + pkg}
}

// Claims converts a proposition into evidence about the package, and nothing
// else.
//
// Refutations become refuting claims rather than being dropped. A source that
// forwards only what supports its conclusion cannot be checked, and the
// polarity model exists precisely so disagreement survives transport.
func (p ResearchProposition) Claims(source, observedAt string) []evidence.Claim {
	subject := PackageSubject(p.Ecosystem, p.Package)
	var out []evidence.Claim

	prov := func() evidence.Provenance {
		return evidence.Provenance{
			Source: source, SourceID: p.Advisory, ObservedAt: observedAt,
			Reference: p.Advisory,
		}
	}

	if s := p.statement(); s != "" {
		out = append(out, evidence.Claim{
			Kind: p.Maturity.kind(), Subject: subject,
			Statement: s, Provenance: prov(),
		})
	}
	for _, r := range p.Refutations {
		out = append(out, evidence.Claim{
			Kind: evidence.KindStatic, Subject: subject,
			Polarity: evidence.PolarityRefutes, Statement: r, Provenance: prov(),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Statement < out[j].Statement })
	return out
}

func (p ResearchProposition) statement() string {
	switch {
	case p.PoCHypothesis != "":
		return p.PoCHypothesis
	case p.TriggerCondition != "":
		return p.TriggerCondition
	case len(p.AffectedSymbols) > 0:
		return "research names " + p.AffectedSymbols[0] + " as affected"
	case p.Advisory != "":
		return p.Advisory + " affects this package"
	default:
		return ""
	}
}

// AppliesLocally reports what a local scan would still have to establish for
// this proposition to matter here.
//
// It returns questions, not answers, and that is the point. Intel can say a
// symbol is dangerous; only the local build can say whether it is referenced,
// only local analysis can say whether anything reaches it, and only an
// authorized run can say whether it fires. A source that answered these would
// be deciding what affects a repository it has never seen.
func (p ResearchProposition) AppliesLocally() []string {
	var q []string
	if len(p.AffectedSymbols) > 0 {
		q = append(q, "does this build reference "+p.AffectedSymbols[0]+"?")
	}
	if p.AffectedConfiguration != "" {
		q = append(q, "is this deployment configured as "+p.AffectedConfiguration+"?")
	}
	if len(p.KnownEntryPoints) > 0 {
		q = append(q, "does this application expose "+p.KnownEntryPoints[0]+"?")
	}
	if p.TriggerCondition != "" {
		q = append(q, "can the trigger condition be reached here?")
	}
	if len(q) == 0 {
		q = append(q, "does this package appear in this build at all?")
	}
	return q
}
