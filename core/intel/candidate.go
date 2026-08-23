package intel

import (
	"github.com/nox-hq/nox/core/evidence"
)

// State is where a candidate sits in the research lifecycle. It is a workflow
// label — a record of what humans and agents have done with the candidate —
// and deliberately not the source of truth for whether the candidate is real.
// That question is answered by the evidence ledger; see Validated.
type State string

// Candidate states.
const (
	// StateObserved — reported, but by a single source. One reporter seeing
	// something a hundred times is still one reporter.
	StateObserved State = "OBSERVED"
	// StateCandidate — corroborated by at least two independent sources, and
	// therefore worth someone's attention.
	StateCandidate State = "CANDIDATE"
	// StateResearching — under active investigation.
	StateResearching State = "RESEARCHING"
	// StateValidated — evidence sufficient to assert the vulnerability is real.
	StateValidated State = "VALIDATED"
	// StateDismissed — investigated and rejected. Kept rather than deleted so
	// the same cluster is not rediscovered and re-escalated forever.
	StateDismissed State = "DISMISSED"
)

// stateRank orders the lifecycle for merges. DISMISSED ranks lowest so that
// merging a dismissed cluster into a live one cannot erase live evidence;
// merging two dismissed clusters still yields DISMISSED.
func (s State) stateRank() int {
	switch s {
	case StateDismissed:
		return 0
	case StateObserved:
		return 1
	case StateCandidate:
		return 2
	case StateResearching:
		return 3
	case StateValidated:
		return 4
	default:
		return 0
	}
}

// Disclosure is how widely a candidate may be spoken about. It governs
// discoverability, and it fails closed.
type Disclosure string

// Disclosure states.
const (
	// DisclosureInternal — known only to the organization that found it. The
	// default for a new candidate.
	DisclosureInternal Disclosure = "INTERNAL"
	// DisclosureUnderReview — submitted to the network for triage.
	DisclosureUnderReview Disclosure = "UNDER_REVIEW"
	// DisclosureMaintainerNotified — the upstream maintainer has been told and
	// the clock is running.
	DisclosureMaintainerNotified Disclosure = "MAINTAINER_NOTIFIED"
	// DisclosureEmbargoed — under a coordinated-disclosure embargo. Publishing
	// it early hands an unpatched vulnerability to attackers.
	DisclosureEmbargoed Disclosure = "EMBARGOED"
	// DisclosurePublic — already published; there is nothing left to protect.
	DisclosurePublic Disclosure = "PUBLIC"
)

// Discoverable reports whether the candidate may be returned by a general
// search of the network.
//
// EMBARGOED and INTERNAL are false, and so is every unrecognised value. Failing
// open here would leak an embargoed vulnerability to anyone who queried the
// package, which is the single worst thing a disclosure system can do; failing
// closed merely hides a record from a search until its state is corrected.
func (d Disclosure) Discoverable() bool {
	switch d {
	case DisclosureUnderReview, DisclosureMaintainerNotified, DisclosurePublic:
		return true
	default:
		return false
	}
}

// restrictiveness orders disclosure states by how much they withhold. Merges
// keep the maximum, so combining an embargoed candidate with a public one can
// never widen the embargoed one's audience.
func (d Disclosure) restrictiveness() int {
	switch d {
	case DisclosurePublic:
		return 0
	case DisclosureMaintainerNotified:
		return 1
	case DisclosureUnderReview:
		return 2
	case DisclosureInternal:
		return 3
	case DisclosureEmbargoed:
		return 4
	default:
		// An unknown state is treated as maximally restrictive, matching
		// Discoverable's fail-closed reading.
		return 4
	}
}

// Candidate is a cluster of observations of the same weakness in the same
// artifact, together with everything nox knows about why it might be real.
type Candidate struct {
	// ID is the stable, quotable identifier derived from Fingerprint.
	ID string `json:"id"`
	// Fingerprint is the cluster identity; see Fingerprint.
	Fingerprint string `json:"fingerprint"`
	// Ecosystem and Package name the affected artifact.
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	// AffectedRange is the version span the observations cover. It widens as
	// clusters merge and is never narrowed by a merge.
	AffectedRange string `json:"affected_range,omitempty"`
	// WeaknessClass is the shared-vocabulary class of the weakness.
	WeaknessClass WeaknessClass `json:"weakness_class"`
	// Summary is a generated one-line description. It is assembled from the
	// candidate's own coordinates rather than copied from a finding message,
	// because a finding message can quote source code.
	Summary string `json:"summary,omitempty"`
	// Ledger holds every claim made about this candidate and is the sole basis
	// for its confidence.
	Ledger evidence.Ledger `json:"ledger"`
	// State is the workflow label; Disclosure is the visibility rule.
	State      State      `json:"state"`
	Disclosure Disclosure `json:"disclosure"`
	// Advisories lists correlated advisory identifiers (OSV, CVE, GHSA).
	Advisories []string `json:"advisories,omitempty"`
	// ObservationCount is how many raw observations went into the cluster. It
	// is reported separately from IndependentSources precisely so that volume
	// can never be mistaken for corroboration.
	ObservationCount int `json:"observation_count"`
	// FirstObserved and LastObserved bound the observation window.
	FirstObserved string `json:"first_observed,omitempty"`
	LastObserved  string `json:"last_observed,omitempty"`
}

// Confidence returns the candidate's aggregate confidence.
//
// It delegates entirely to the evidence ledger. There is no intel-specific
// scoring: a second scheme would eventually disagree with the first, and the
// disagreement would surface to a user as a confident wrong answer.
func (c *Candidate) Confidence() evidence.Confidence {
	if c == nil {
		return evidence.ConfidenceLow
	}
	return c.Ledger.Confidence()
}

// IndependentSources returns the number of distinct reporters behind the
// candidate. This is the number that matters for corroboration;
// ObservationCount is not.
func (c *Candidate) IndependentSources() int {
	if c == nil {
		return 0
	}
	return c.Ledger.IndependentSources()
}

// Validated reports whether the evidence establishes the vulnerability as real.
//
// It asks the ledger, never the State field. State is a label a human or an
// agent can set; validation is a property of the evidence, and letting a label
// assert it would let a workflow click promote a hypothesis to a fact.
func (c *Candidate) Validated() bool {
	if c == nil {
		return false
	}
	return c.Ledger.Confidence() == evidence.ConfidenceConfirmed
}

// addClaim appends a claim unless an identical one is already present, so
// re-running correlation or re-ingesting the same trace does not inflate a
// ledger with duplicates.
func (c *Candidate) addClaim(cl evidence.Claim) bool {
	key := claimKey(cl)
	for i := range c.Ledger.Claims {
		if claimKey(c.Ledger.Claims[i]) == key {
			return false
		}
	}
	c.Ledger.Add(cl)
	return true
}

// claimKey identifies a claim for deduplication: what was said, by whom, when,
// and citing what.
func claimKey(cl evidence.Claim) string {
	p := cl.Provenance
	return string(cl.Kind) + "\x00" + cl.Statement + "\x00" + p.Source + "\x00" +
		p.SourceID + "\x00" + p.Reference + "\x00" + p.ObservedAt
}

// syncState lifts the workflow label to match the evidence. It only ever
// promotes: a human's DISMISSED or RESEARCHING is not overwritten by a weaker
// automatic reading, and validation is asserted only when the ledger supports
// it.
func (c *Candidate) syncState() {
	switch {
	case c.State == StateDismissed:
		return
	case c.Validated():
		c.State = StateValidated
	case c.IndependentSources() >= 2 && c.State.stateRank() < StateCandidate.stateRank():
		c.State = StateCandidate
	case c.State == "":
		c.State = StateObserved
	}
}
