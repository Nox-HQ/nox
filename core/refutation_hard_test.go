package core

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/reach"
)

// Milestone B: the refutation corpus must contain intentionally difficult cases
// — reflection, dynamic dispatch, FFI, unsupported semantics, bounded analysis
// — and none of them may incorrectly reach a negative.
//
// testdata/refutation-suite answers the other question: does nox refute what it
// SHOULD? This one answers the dangerous one: does nox refuse to refute what it
// cannot see? Automated negative evidence is the most dangerous capability in
// the tool, because a wrong positive costs an afternoon and a wrong negative
// costs the finding.

// TestTheHardCorpusIsActuallyAnalysed comes first, because the corpus is
// worthless if nothing runs on it.
//
// The first version of these fixtures used a bare function parameter as the
// tainted value. nox produced zero findings, zero subjects and zero claims, so
// the acceptance criterion below passed while testing nothing at all — the
// mechanism was never reached. Giving the fixtures a real source
// (`r.URL.Query().Get`) is what makes the corpus exercise the taint engine, and
// h3 firing is the proof that it does.
func TestTheHardCorpusIsActuallyAnalysed(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := RunScanWithOptions("../testdata/refutation-hard",
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Reasoning.Subjects()) == 0 {
		t.Fatal("the hard corpus produced no subjects, so the analysis never ran on " +
			"it and every assertion about refutation safety below is vacuous")
	}
	var taint bool
	for _, f := range res.Findings.Findings() {
		if strings.HasPrefix(f.RuleID, "TAINT-") {
			taint = true
		}
	}
	if !taint {
		t.Error("no taint finding on the hard corpus: the engine whose refutations " +
			"this corpus is about is not reaching it")
	}
}

// TestNoUnearnedNegativeOnTheHardCorpus is the acceptance criterion.
//
// Every file here contains a real flow that a static analysis cannot follow.
// The correct outcome for each is silence or an explicit unknown. What must
// never appear is a NEGATIVE — a refuting claim, a capability conclusion of
// `negative`, or a reach outcome of `refuted` — because each of those is a
// universal statement, and no analysis that could not resolve the callee is
// entitled to make one.
func TestNoUnearnedNegativeOnTheHardCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := RunScanWithOptions("../testdata/refutation-hard",
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	for _, s := range res.Reasoning.Subjects() {
		for _, c := range res.Reasoning.About(s).Claims {
			if c.Refutes() {
				t.Errorf("%v carries a refutation on a flow the analysis cannot "+
					"follow: %q. Not finding a path is an existential search coming "+
					"up empty, not a universal claim that none exists", s, c.Statement)
			}
		}
	}

	for _, s := range res.Coverage.Subjects() {
		for _, c := range capability.All() {
			if res.Coverage.State(s, c) == capability.Negative {
				t.Errorf("%v records a NEGATIVE conclusion for %s. capability.Negative "+
					"is the one state that may suppress a finding, and it must never "+
					"come from an analysis that was defeated", s, c)
			}
		}
	}

	for _, f := range res.Findings.Findings() {
		if f.Metadata["reach_outcome"] == string(reach.Refuted) {
			t.Errorf("%s reports a refuted reachability level on a construct the "+
				"analysis cannot model", f.RuleID)
		}
	}
}

// TestSilenceHereIsNotYetRecognisedIncompleteness records what the corpus
// measured, including the part that is not yet good.
//
// Four of the five cases produce nothing at all: no candidate, no claim, no
// capability state. That is SAFE — nox states no negative it has not earned,
// which is the criterion — but it is safe by silence rather than by design. nox
// does not currently recognise that reflection or dynamic dispatch defeated it;
// it simply never formed a candidate.
//
// The distinction matters for what comes next. Milestone A shipped the
// Limitation vocabulary — unresolved_dispatch, reflection, dynamic_loading —
// and nothing emits it yet, so `nox why` cannot say "the analysis stopped at an
// unresolved dispatch" and says nothing instead. A more capable engine that
// followed PART of one of these flows could conclude "no path" where it owes
// the reader "could not resolve the callee", and this test would not catch it,
// because the claim would be about a subject that exists.
//
// It is written as a measurement rather than an assertion of the counts, so it
// keeps reporting as the engine improves instead of failing on progress.
func TestSilenceHereIsNotYetRecognisedIncompleteness(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := RunScanWithOptions("../testdata/refutation-hard",
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var withLimitation int
	for _, f := range res.Findings.Findings() {
		if f.Metadata["reach_scope"] != "" && strings.Contains(f.Metadata["reach_scope"], "incomplete") {
			withLimitation++
		}
	}
	t.Logf("hard corpus: %d finding(s) from 5 cases, %d recording a named limitation. "+
		"The remainder are silent — safe, because silence states nothing, but not "+
		"yet the engine saying what defeated it.",
		len(res.Findings.Findings()), withLimitation)
}
