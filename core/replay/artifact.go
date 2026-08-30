// Package replay persists the evidence behind a scan and re-derives its
// verdicts from that evidence alone.
//
// It is Track I of the evidence-native programme, and its scope is deliberately
// the narrow half. Reproducing a whole scan means pinning the rule set, the
// analyzer versions, the OSV snapshot and the intelligence snapshot, and every
// one of those is a separate problem. Re-deriving the ADJUDICATION needs only
// the ledger and the adjudicator, and it answers the question an operator
// actually asks about a result they are looking at: why did it say that?
//
// # Why this exists as a file rather than as part of findings.json
//
// The ledger is out-of-band during a scan for a measured reason: carried inline
// on every Finding it projects to 6.62 GiB against 3.48 GiB bare on the largest
// repository nox has scanned (docs/benchmarks/2026-Q3/ledger-budget.md). That
// argument is about the default path, which every scan pays. An artifact
// written on request, once, is a different proposition — nobody pays for it
// unless they asked, and the scan that did not ask is byte-identical to before.
package replay

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/fsutil"
)

// SchemaVersion is the artifact format's own version, independent of the
// adjudicator's. A reader that does not recognise it must refuse rather than
// guess: a partially-understood evidence file is worse than none, because it
// looks like an answer.
const SchemaVersion = "1.0.0"

// Artifact is everything needed to re-derive a scan's verdicts.
//
// The five things Milestone 9.1 asks to be reconstructible map onto it
// directly: input identity is Meta, capability state is Capabilities, claims
// and their provenance are Subjects, relationships are Relations, and the
// adjudication result is Findings.
type Artifact struct {
	Meta         Meta                `json:"meta"`
	Capabilities []CapabilityState   `json:"capabilities,omitempty"`
	Subjects     []SubjectEvidence   `json:"subjects"`
	Relations    []evidence.Relation `json:"relations,omitempty"`
	Findings     []FindingVerdict    `json:"findings"`
}

// Meta is the artifact's input identity.
type Meta struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	ToolName      string `json:"tool_name"`
	ToolVersion   string `json:"tool_version"`
	// AdjudicatorVersion is what makes a replay interpretable. A verdict that
	// differs under the same version is a defect; under a different version it
	// is a change, and only the artifact can say which.
	AdjudicatorVersion string `json:"adjudicator_version"`
	// FingerprintVersion is recorded because a fingerprint is how a verdict is
	// matched back to a finding. Replaying against findings computed under a
	// different algorithm would silently match nothing.
	FingerprintVersion int `json:"fingerprint_version"`
	// Target is the scan root as given. Kept as the operator wrote it rather
	// than resolved, so the artifact does not leak an absolute path from the
	// machine that produced it.
	Target string `json:"target"`
	// Offline records the zero-network guarantee, as findings.json does.
	Offline bool `json:"offline"`
}

// CapabilityState is what one analysis capability concluded across the scan.
//
// Counts rather than per-subject states, deliberately. The per-subject matrix
// is large and its detail belongs to the scan; what a replay needs is whether
// the capability answered at all, which is the same question the policy gate
// asks and the same one that separates "we determined nothing" from "we
// determined nothing was there".
type CapabilityState struct {
	Capability   string `json:"capability"`
	Provided     bool   `json:"provided"`
	Answered     int    `json:"answered"`
	Inconclusive int    `json:"inconclusive"`
}

// SubjectEvidence is one subject's complete ledger, provenance included.
type SubjectEvidence struct {
	Subject evidence.Subject `json:"subject"`
	Claims  []evidence.Claim `json:"claims"`
}

// FindingVerdict is what adjudication concluded about one finding, stored so a
// replay has something to disagree with.
//
// AnalyzerConfidence is here alongside the adjudicated one because they are
// different quantities (Track C5) and a replay that carried only one of them
// could not reproduce the divergence report.
type FindingVerdict struct {
	Fingerprint        string           `json:"fingerprint"`
	RuleID             string           `json:"rule_id"`
	Subject            evidence.Subject `json:"subject"`
	AnalyzerConfidence string           `json:"analyzer_confidence"`
	EvidenceConfidence string           `json:"evidence_confidence"`
	Exploitability     string           `json:"exploitability"`
	Conflicted         bool             `json:"conflicted,omitempty"`
	Rationale          string           `json:"rationale"`
}

// Sort orders every slice in the artifact.
//
// Determinism is the product here, not a nicety: an artifact that reorders
// between two identical scans cannot be diffed, and "same inputs, same outputs"
// is the property nox claims on its front page. Maps are iterated in random
// order in Go, and every slice below is built from one.
func (a *Artifact) Sort() {
	sort.Slice(a.Capabilities, func(i, j int) bool {
		return a.Capabilities[i].Capability < a.Capabilities[j].Capability
	})
	sort.Slice(a.Subjects, func(i, j int) bool {
		return a.Subjects[i].Subject.String() < a.Subjects[j].Subject.String()
	})
	// Claims within a subject are deliberately NOT sorted. Their order is
	// load-bearing: the kernel breaks strength ties by taking the earliest
	// claim, so the claim that carried a verdict — and therefore the rationale
	// an operator read — is a function of the order they were recorded in.
	//
	// This was found rather than reasoned. An earlier draft sorted them by
	// kind, source and statement, which looked tidy and changed the rationale
	// on 10 of 37 findings: every one a tie between heuristics, where the
	// reordering promoted a different tied claim. The artifact was faithful
	// about the labels and wrong about the sentence, which is the half a person
	// actually reads.
	//
	// The subjects, relations, findings and capabilities above ARE sorted,
	// because each is built from a Go map and has no meaningful order of its
	// own.
	sort.Slice(a.Relations, func(i, j int) bool {
		l, r := a.Relations[i], a.Relations[j]
		if l.From.String() != r.From.String() {
			return l.From.String() < r.From.String()
		}
		if l.Kind != r.Kind {
			return l.Kind < r.Kind
		}
		return l.To.String() < r.To.String()
	})
	sort.Slice(a.Findings, func(i, j int) bool {
		if a.Findings[i].RuleID != a.Findings[j].RuleID {
			return a.Findings[i].RuleID < a.Findings[j].RuleID
		}
		return a.Findings[i].Fingerprint < a.Findings[j].Fingerprint
	})
}

// Encode serialises the artifact, sorted, with a trailing newline.
func (a *Artifact) Encode() ([]byte, error) {
	a.Sort()
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding evidence artifact: %w", err)
	}
	return append(data, '\n'), nil
}

// WriteFile writes the artifact atomically.
func (a *Artifact) WriteFile(path string) error {
	data, err := a.Encode()
	if err != nil {
		return err
	}
	if err := fsutil.AtomicWriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing evidence artifact: %w", err)
	}
	return nil
}

// Load reads an artifact and refuses a schema it does not understand.
func Load(path string) (*Artifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading evidence artifact %s: %w", path, err)
	}
	var a Artifact
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parsing evidence artifact %s: %w", path, err)
	}
	if a.Meta.SchemaVersion != SchemaVersion {
		// Refusing beats guessing. A reader that half-understands an evidence
		// file produces a confident answer from an unknown subset of the
		// evidence, which is indistinguishable from a correct one.
		return nil, fmt.Errorf("evidence artifact %s has schema version %q, this build understands %q",
			path, a.Meta.SchemaVersion, SchemaVersion)
	}
	return &a, nil
}

// LedgerFor returns the ledger stored for a subject, and whether one was.
func (a *Artifact) LedgerFor(s evidence.Subject) (evidence.Ledger, bool) {
	for i := range a.Subjects {
		if a.Subjects[i].Subject == s {
			return evidence.Ledger{Claims: a.Subjects[i].Claims}, true
		}
	}
	return evidence.Ledger{}, false
}
