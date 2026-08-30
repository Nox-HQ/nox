package core

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/capability"
)

// TestEndToEndEvidenceChain runs one real scan over the committed precision
// suite and checks that every stage of the evidence pipeline actually produced
// something.
//
// The unit tests each verify one stage in isolation, which is exactly how a
// pipeline passes its whole test suite while being disconnected in the middle.
// This is the test that fails if a stage stops being reached: refiners record,
// findings carry supporting claims, adjudication runs, divergence is measured,
// capability coverage is populated. Silence at any stage fails, because
// silence is precisely what a disconnected stage looks like.
//
// The target is the committed corpus rather than an arbitrary repository, and
// that choice is load-bearing. Running this against a real project first showed
// two of these assertions failing on a codebase that simply had nothing to
// refute and no diverging findings — legitimate outcomes that would make the
// test flaky and, worse, would train a reader to ignore it. The corpus
// guarantees the conditions the assertions depend on.
func TestEndToEndEvidenceChain(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}

	res, err := RunScanWithOptions("../testdata/precision-suite",
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	all := res.Findings.Findings()
	if len(all) == 0 {
		t.Fatal("the corpus produced no findings; every assertion below would be vacuous")
	}

	// Stage 1 — refiners record why they dropped a candidate.
	recorded, unusable := res.Reasoning.Stats()
	if recorded == 0 {
		t.Error("no claims were recorded; the reasoning store is not being reached")
	}
	if unusable != 0 {
		t.Errorf("%d claim(s) were filed against an unusable subject — unretrievable, "+
			"which from every other angle looks exactly like working", unusable)
	}

	reported := make(map[evidence.Subject]bool, len(all))
	for _, f := range all {
		reported[SubjectForFinding(f)] = true
	}

	var refutations int
	for _, s := range res.Reasoning.Subjects() {
		if reported[s] {
			continue
		}
		for _, c := range res.Reasoning.About(s).Claims {
			if !c.Refutes() {
				t.Errorf("dropped candidate %s recorded a %s claim; a drop is a refutation",
					s, c.Polarity.Effective())
				continue
			}
			if c.Statement == "" {
				t.Errorf("dropped candidate %s recorded no reason", s)
			}
			refutations++
		}
	}
	if refutations == 0 {
		t.Error("no candidate was refuted across the whole corpus; either the refiners " +
			"stopped recording, or they stopped running")
	}

	// Stage 2 — every reported finding has a recorded reason for existing.
	for _, f := range all {
		ledger := res.Reasoning.About(SubjectForFinding(f))
		var supported bool
		for _, c := range ledger.Claims {
			if c.Supports() {
				supported = true
			}
		}
		if !supported {
			t.Errorf("finding %s at %s:%d has no supporting claim",
				f.RuleID, f.Location.FilePath, f.Location.StartLine)
		}
	}

	// Stage 3 — adjudication ran, and never overstated what a scan can know.
	for _, f := range all {
		if f.Exploitability != string(evidence.Potential) {
			t.Errorf("finding %s adjudicated to %q; a scan executes nothing, so "+
				"POTENTIAL is the only honest state", f.RuleID, f.Exploitability)
		}
	}

	// Stage 4 — divergence was measured, not assumed.
	if len(res.Divergences) == 0 {
		t.Error("no divergence reported across the corpus. Either every analyzer's " +
			"confidence now matches its evidence — which would be remarkable — or " +
			"the comparison stopped running")
	}

	// Stage 5 — capability coverage, and the rule that makes it worth having.
	if res.Coverage.Len() == 0 {
		t.Error("no capability results recorded")
	}
	if len(res.Capabilities.Missing()) == 0 {
		t.Error("the scan claims to be missing no capability, which cannot be true " +
			"of a scanner that never executes the code it reads")
	}
	for _, f := range all {
		subject := SubjectForFinding(f)
		if res.Coverage.State(subject, capability.DynamicVerification).Conclusive() {
			t.Errorf("finding %s claims dynamic verification; nox scan executes nothing",
				f.RuleID)
		}
		for _, g := range res.Coverage.Gaps(subject) {
			if g.State.SuppressesFinding() {
				t.Errorf("finding %s has gap %+v reported as suppressing; only a "+
					"conclusive negative may hide a finding", f.RuleID, g)
			}
		}
	}
}
