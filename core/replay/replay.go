package replay

import (
	"fmt"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/adjudicate"
)

// Divergence is one finding whose replayed verdict differs from the one stored.
type Divergence struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	Field       string `json:"field"`
	Stored      string `json:"stored"`
	Replayed    string `json:"replayed"`
}

// Result is what a replay establishes.
type Result struct {
	// Checked is how many stored verdicts were re-derived.
	Checked int `json:"checked"`
	// Missing lists findings whose subject has no ledger in the artifact.
	// Distinct from a divergence: nothing was re-derived, so nothing disagreed.
	Missing []string `json:"missing,omitempty"`
	// Divergences are verdicts that came out differently.
	Divergences []Divergence `json:"divergences,omitempty"`
	// VersionChanged is true when the artifact was produced by a different
	// adjudicator. Then a divergence is a CHANGE, not a defect, and saying so
	// is the difference between a useful replay and an alarm nobody trusts.
	VersionChanged bool `json:"version_changed"`
	// ArtifactVersion and ThisVersion are reported either way, because "they
	// match" is itself worth stating: it is what licenses reading a divergence
	// as a regression.
	ArtifactVersion string `json:"artifact_adjudicator_version"`
	ThisVersion     string `json:"this_adjudicator_version"`
}

// Reproduced reports whether every stored verdict came back identical.
//
// A missing ledger counts as not reproduced. The alternative — treating "no
// evidence to replay" as agreement — would make an empty artifact reproduce
// perfectly, which is the shape of every false all-clear in this codebase.
func (r Result) Reproduced() bool {
	return len(r.Divergences) == 0 && len(r.Missing) == 0 && r.Checked > 0
}

// Summary is the one line a person reads.
func (r Result) Summary() string {
	switch {
	case r.Checked == 0:
		return "nothing was replayed: the artifact records no verdicts"
	case r.VersionChanged:
		return fmt.Sprintf("%d verdict(s) replayed under adjudicator %s against an artifact from %s; "+
			"%d differ, which is a change in adjudication rather than a defect",
			r.Checked, r.ThisVersion, r.ArtifactVersion, len(r.Divergences))
	case r.Reproduced():
		return fmt.Sprintf("%d verdict(s) reproduced exactly under adjudicator %s", r.Checked, r.ThisVersion)
	default:
		return fmt.Sprintf("%d of %d verdict(s) did not reproduce under adjudicator %s, and %d had no evidence to replay",
			len(r.Divergences), r.Checked, r.ThisVersion, len(r.Missing))
	}
}

// Replay re-derives every stored verdict from the artifact's own evidence.
//
// It reads nothing but the artifact. That is the point of Milestone 9.2: the
// repository may have changed, the rules may have changed, the network may be
// gone, and the question "does this evidence still support this verdict?" is
// still answerable — because it never depended on any of them.
func Replay(a *Artifact) Result {
	res := Result{
		ArtifactVersion: a.Meta.AdjudicatorVersion,
		ThisVersion:     adjudicate.Version,
		VersionChanged:  a.Meta.AdjudicatorVersion != adjudicate.Version,
	}
	for _, stored := range a.Findings {
		ledger, ok := a.LedgerFor(stored.Subject)
		if !ok {
			res.Missing = append(res.Missing, stored.Fingerprint)
			continue
		}
		res.Checked++
		got := adjudicate.Adjudicate(ledger, stored.Subject)

		add := func(field, was, now string) {
			if was == now {
				return
			}
			res.Divergences = append(res.Divergences, Divergence{
				Fingerprint: stored.Fingerprint, RuleID: stored.RuleID,
				Field: field, Stored: was, Replayed: now,
			})
		}
		add("exploitability", stored.Exploitability, string(got.Exploitability))
		add("evidence_confidence", stored.EvidenceConfidence, string(got.Confidence))
		add("conflicted", boolText(stored.Conflicted), boolText(got.Conflicted))
		// The rationale is part of the verdict: it is the sentence a person
		// read and acted on. A replay that reproduced the labels and not the
		// explanation has not reproduced what the operator saw.
		add("rationale", stored.Rationale, got.Rationale)
	}
	return res
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// VerdictFor derives a verdict from an artifact's evidence about one subject.
// It is the single-finding form of Replay, for explanation rather than
// verification.
func VerdictFor(a *Artifact, s evidence.Subject) (adjudicate.Verdict, bool) {
	ledger, ok := a.LedgerFor(s)
	if !ok {
		return adjudicate.Verdict{}, false
	}
	return adjudicate.Adjudicate(ledger, s), true
}
