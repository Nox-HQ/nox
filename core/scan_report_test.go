package core

import (
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/findings"
)

// The adapters now trust ScanResult.JSONReporter to carry everything the
// artifact must state. The conformance guard checks that they call it; nothing
// there checks that it still fills anything in.
//
// That is the shape of hole this whole milestone is about — a check written
// against the wrong input passes while the thing it guards is empty — so the
// constructor is pinned behaviourally, field by field, against a result that
// has something to say in each one.
func TestJSONReporterCarriesEverythingTheArtifactMustState(t *testing.T) {
	reg := capability.DefaultRegistry()
	cov := capability.NewCoverage(reg)
	cov.Record(SubjectForFinding(findings.Finding{RuleID: "SEC-001", Location: findings.Location{FilePath: "a.go"}}),
		capability.LexicalContext, capability.Positive)

	r := &ScanResult{
		SASTProfile: map[string]string{"go": "deep"},
		Degradations: []Degradation{{
			Kind: degrade.OSV, Detail: "d", Impact: "i",
		}},
		Enrichments:  []findings.Enrichment{{FindingFingerprint: "fp"}},
		Capabilities: reg,
		Coverage:     cov,
	}

	rep := r.JSONReporter("test")
	if len(rep.SASTLanguages) == 0 {
		t.Error("SASTLanguages is empty: the depth strategy will not be auditable in the artifact")
	}
	if len(rep.Degradations) == 0 {
		t.Error("Degradations is empty: a scan whose checks failed will read as a clean scan")
	}
	if len(rep.Enrichments) == 0 {
		t.Error("Enrichments is empty: a plugin that annotates will look like one that did not run")
	}
	if len(rep.Capabilities) != len(capability.All()) {
		t.Fatalf("Capabilities has %d rows, want one per capability (%d): a report with no matrix "+
			"looks like one from an installation that could answer every question",
			len(rep.Capabilities), len(capability.All()))
	}
	var answered bool
	for _, c := range rep.Capabilities {
		if c.Capability == "lexical_context" && c.Answered == 1 {
			answered = true
		}
	}
	if !answered {
		t.Error("the recorded coverage did not reach the reporter; the matrix is derived from " +
			"nothing and would be all zeroes on every scan")
	}
}

// The SARIF constructor carries the matrix and deliberately does NOT carry the
// rule catalog — 1,500+ descriptors would blow the MCP response budget, so that
// stays the caller's size decision. Pinning both halves keeps a later "make it
// consistent" change from quietly reintroducing the overflow.
func TestSARIFReporterCarriesCapabilitiesButNotTheCatalog(t *testing.T) {
	reg := capability.DefaultRegistry()
	r := &ScanResult{Capabilities: reg, Coverage: capability.NewCoverage(reg)}

	rep := r.SARIFReporter("test")
	if len(rep.Capabilities) != len(capability.All()) {
		t.Errorf("Capabilities has %d rows, want %d", len(rep.Capabilities), len(capability.All()))
	}
	if rep.Rules != nil {
		t.Error("SARIFReporter set Rules; the full catalog is the caller's size decision, and " +
			"embedding it here overflows the MCP response budget")
	}
}

// A nil result must not panic and must not fabricate a matrix. Absence is
// honest; nine rows of zeroes claiming a full installation is not.
func TestNilScanResultProducesNoMatrix(t *testing.T) {
	var r *ScanResult
	if got := len(r.JSONReporter("test").Capabilities); got != 0 {
		t.Errorf("nil result produced %d capability rows", got)
	}
	if got := len(r.SARIFReporter("test").Capabilities); got != 0 {
		t.Errorf("nil result produced %d SARIF capability rows", got)
	}
}
