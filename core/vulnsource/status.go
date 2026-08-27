package vulnsource

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/nox-hq/nox/core/evidence"
)

// Status is the epistemic standing of a record: what kind of thing is being
// claimed, not how severe it is.
//
// OSV answers a closed question — is there a *published* advisory for this
// exact (ecosystem, package, version)? A richer source answers an open one, and
// those two answers do not have the same standing. Rendering them identically
// is the single most damaging thing a tool in this category can do, so status
// travels with the record all the way to the report rather than being inferred
// at the edge.
type Status string

const (
	// StatusPublished — a published advisory asserts this. What OSV returns,
	// and the only status that gates a build by default.
	StatusPublished Status = "PUBLISHED"

	// StatusCandidate — an emerging issue with no published advisory yet.
	// Corroborated across reporters, perhaps, but not disclosed. Reported and
	// labelled THEORETICAL; never gating on its own.
	StatusCandidate Status = "CANDIDATE"

	// StatusEmbargoed — under coordinated disclosure. Reaching a client at all
	// implies entitlement; it is never discoverable through general lookup.
	StatusEmbargoed Status = "EMBARGOED"
)

// Valid reports whether s is a status nox understands. An unrecognised status
// is not treated as published: a source cannot obtain gating standing by
// sending a word this build has never heard of.
func (s Status) Valid() bool {
	switch s {
	case StatusPublished, StatusCandidate, StatusEmbargoed:
		return true
	default:
		return false
	}
}

// Gating reports whether a record with this status may gate a build on its own.
//
// Only a published advisory does. An uncorroborated candidate that fails a
// build the way a CVE does would burn the feature on its first false positive,
// and an operator who starts ignoring candidate findings is worse off than one
// who never saw them.
func (s Status) Gating() bool { return s.EffectiveStatus() == StatusPublished }

// EffectiveStatus resolves the zero value and anything unrecognised.
//
// Empty means published: every record predating this field came from OSV, which
// serves published advisories only. Anything unrecognised resolves to candidate
// — the non-gating side — so an unknown value fails closed rather than
// acquiring the standing of a disclosed CVE.
func (s Status) EffectiveStatus() Status {
	switch {
	case s == "":
		return StatusPublished
	case s.Valid():
		return s
	default:
		return StatusCandidate
	}
}

// Intelligence carries what a source knows beyond the advisory itself.
//
// It is a separate struct rather than fields inlined on Record so that a record
// which came from a plain advisory database is visibly free of intelligence
// claims, instead of carrying zero values that read like assertions.
type Intelligence struct {
	// Status is the record's epistemic standing. Empty means published.
	Status Status `json:"status,omitempty"`

	// Corroboration is the number of DISTINCT reporters, never the number of
	// observations. One project scanning itself a thousand times is one source;
	// treating repetition as corroboration is how a single noisy installation
	// manufactures consensus.
	Corroboration int `json:"corroboration,omitempty"`

	// Evidence is the claim ledger behind the record. Confidence and
	// exploitability are derived from it by core/evidence, which owns the rule
	// that CONFIRMED requires deterministic evidence — that rule is not
	// restated here, on either side of the wire.
	Evidence *evidence.Ledger `json:"evidence,omitempty"`

	// SourceName identifies which source returned this record, so a finding can
	// be traced to the thing that claimed it.
	SourceName string `json:"source_name,omitempty"`
}

// Theoretical reports whether the record describes a path nobody has
// demonstrated. Such a record must be labelled wherever it is rendered — CLI,
// JSON, SARIF, MCP — because presenting a projection as an observation is the
// failure this whole model exists to prevent.
func (i *Intelligence) Theoretical() bool {
	if i == nil {
		return false
	}
	if i.Status.EffectiveStatus() == StatusPublished {
		return false
	}
	if i.Evidence == nil {
		return true
	}
	return !i.Evidence.HasDeterministic()
}

// CandidateIDPrefix marks an identifier nox derived rather than one an advisory
// database issued.
const CandidateIDPrefix = "NOX-CAND-"

// CandidateID derives a stable identifier for a record with no published
// advisory ID.
//
// SARIF, SBOM, and VEX all key on a vulnerability ID, so a candidate without
// one cannot be rendered, waived, or baselined. The identifier hashes only the
// facts that make two reports the same logical issue — ecosystem, package,
// normalised version range, weakness class — so two installations describing
// one issue derive the same ID, and the ID itself reveals nothing about either
// of them. No paths, no contents, no reporter.
func CandidateID(ecosystem, pkg, versionRange, weakness string) string {
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	h := sha256.Sum256([]byte(strings.Join([]string{
		norm(ecosystem), norm(pkg), norm(versionRange), norm(weakness),
	}, "\x00")))
	return CandidateIDPrefix + hex.EncodeToString(h[:])[:12]
}
