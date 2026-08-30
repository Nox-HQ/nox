package replay

import (
	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/adjudicate"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reasoning"
)

// Inputs is everything the builder needs that it cannot derive.
//
// The timestamp is passed in rather than read, following the kernel's rule: a
// package that reads a clock cannot be tested for determinism, and every
// derived verdict has to be reproducible from its inputs alone.
type Inputs struct {
	GeneratedAt        string
	ToolName           string
	ToolVersion        string
	Target             string
	Offline            bool
	FingerprintVersion int
}

// SubjectOf maps a finding to the subject its claims are filed against. The
// scan supplies it so this package does not have to duplicate the derivation —
// two implementations of that mapping would silently disagree and the artifact
// would record evidence about subjects nothing looks up.
type SubjectOf func(findings.Finding) evidence.Subject

// Build assembles an artifact from what a scan established.
//
// A nil store yields an artifact with no evidence, and that is honest rather
// than empty-by-accident: a scan that did not record reasoning has nothing to
// replay, and Replay reports Checked=0 rather than a clean reproduction.
func Build(in Inputs, store *reasoning.Store, cov *capability.Coverage,
	reg *capability.Registry, fs []findings.Finding, subjectOf SubjectOf) *Artifact {

	a := &Artifact{Meta: Meta{
		SchemaVersion:      SchemaVersion,
		GeneratedAt:        in.GeneratedAt,
		ToolName:           in.ToolName,
		ToolVersion:        in.ToolVersion,
		AdjudicatorVersion: adjudicate.Version,
		FingerprintVersion: in.FingerprintVersion,
		Target:             in.Target,
		Offline:            in.Offline,
	}}

	for _, c := range capability.All() {
		answered, inconclusive := cov.Answered(c)
		a.Capabilities = append(a.Capabilities, CapabilityState{
			Capability:   string(c),
			Provided:     reg.Provided(c),
			Answered:     answered,
			Inconclusive: inconclusive,
		})
	}

	if store != nil {
		for _, s := range store.Subjects() {
			ledger := store.About(s)
			if len(ledger.Claims) == 0 {
				continue
			}
			a.Subjects = append(a.Subjects, SubjectEvidence{Subject: s, Claims: ledger.Claims})
		}
		a.Relations = store.Relations().Relations
	}

	for _, f := range fs {
		subject := subjectOf(f)
		v, ok := VerdictFor(a, subject)
		if !ok {
			// No evidence about this finding. Recorded anyway, with the
			// verdict the scan reported: an artifact that quietly omitted it
			// would replay clean while saying nothing about a finding the
			// operator can see in findings.json.
			a.Findings = append(a.Findings, FindingVerdict{
				Fingerprint: f.Fingerprint, RuleID: f.RuleID, Subject: subject,
				AnalyzerConfidence: string(f.Confidence),
				EvidenceConfidence: f.EvidenceConfidence,
				Exploitability:     f.Exploitability,
			})
			continue
		}
		a.Findings = append(a.Findings, FindingVerdict{
			Fingerprint: f.Fingerprint, RuleID: f.RuleID, Subject: subject,
			AnalyzerConfidence: string(f.Confidence),
			EvidenceConfidence: string(v.Confidence),
			Exploitability:     string(v.Exploitability),
			Conflicted:         v.Conflicted,
			Rationale:          v.Rationale,
		})
	}

	a.Sort()
	return a
}
