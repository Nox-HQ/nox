package core

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
)

// Track C5. The plan said Finding should stop carrying an analyzer-authored
// verdict and become the output of adjudication, with Confidence demoted from
// authority to input.
//
// It was measured first, and the measurement stopped it. These tests are that
// measurement, committed, so the idea cannot come back without the number
// coming back with it.

// TestAdjudicatedConfidenceCannotReachHighOnAStaticScan is the structural fact
// the whole decision rests on.
//
// The kernel puts HIGH at strength 70 — source_confirmed, controlled
// reproduction, a public advisory. A pattern scanner's strongest claim is
// KindStatic at 40, which is MEDIUM. So "adjudicated confidence" has no top of
// scale available to it here, and never will while nox is a static scanner:
// the missing strength comes from executing something or from someone else
// reporting it, not from analysing harder.
//
// This is not a defect in either component. It is what makes them different
// quantities, and it is why one cannot be substituted for the other.
func TestAdjudicatedConfidenceCannotReachHighOnAStaticScan(t *testing.T) {
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
		t.Fatal("no findings; every assertion below would be vacuous")
	}

	for _, f := range all {
		if f.EvidenceConfidence == "" {
			t.Fatalf("%s at %s carries no evidence confidence on an adjudicating scan",
				f.RuleID, f.Location.FilePath)
		}
		switch evidence.Confidence(f.EvidenceConfidence) {
		case evidence.ConfidenceHigh, evidence.ConfidenceConfirmed:
			t.Errorf("%s at %s reached %s from a static scan. If a deterministic "+
				"source now clears strength 70, this test is the place to say so — "+
				"and the C5 decision it documents deserves revisiting with the new "+
				"number", f.RuleID, f.Location.FilePath, f.EvidenceConfidence)
		}
	}
}

// TestTheFlipWouldHaveEmptiedTheTopOfTheScale is the number that decided C5,
// kept executable.
//
// Adopting adjudicated confidence as the finding's confidence does not
// recalibrate the scale, it removes the top of it. `--min-confidence high`
// would return nothing — not on this corpus, on every project, permanently,
// because no static scan clears strength 70. A filter that always returns
// nothing is indistinguishable from a clean repository, which is the one
// outcome this programme exists to prevent.
//
// The assertion is that the damage is still real, so that if the ledger ever
// gains a way to reach HIGH honestly, this fails and the decision gets made
// again with the new evidence rather than inherited from a comment.
func TestTheFlipWouldHaveEmptiedTheTopOfTheScale(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := RunScanWithOptions("../testdata/precision-suite",
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	all := res.Findings.Findings()

	var visibleNow, visibleAfterFlip int
	for _, f := range all {
		if ConfidenceMeetsThreshold(f.Confidence, findings.ConfidenceHigh) {
			visibleNow++
		}
		if ConfidenceMeetsThreshold(onAnalyzerScale(f.EvidenceConfidence), findings.ConfidenceHigh) {
			visibleAfterFlip++
		}
	}
	if visibleNow == 0 {
		t.Fatal("no finding is high-confidence today, so the corpus cannot show what " +
			"the flip would have cost")
	}
	if visibleAfterFlip != 0 {
		t.Errorf("--min-confidence high would still show %d of %d findings after the "+
			"flip. The evidence ledger has gained something it did not have when C5 "+
			"was decided; re-measure before treating that decision as settled",
			visibleAfterFlip, len(all))
	}
	t.Logf("--min-confidence high: %d of %d findings visible today, %d after the "+
		"flip the plan called for", visibleNow, len(all), visibleAfterFlip)
}

// TestAdjudicationDoesNotAuthorConfidence. The analyzer keeps authorship, and
// the evidence gets its own field to disagree in.
//
// Without this, the two-scale design decays into the one-scale design the
// moment somebody "simplifies" the adjudicator, and every symptom would be a
// filter quietly showing less.
func TestAdjudicationDoesNotAuthorConfidence(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	quiet, err := RunScanWithOptions("../testdata/precision-suite", ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	loud, err := RunScanWithOptions("../testdata/precision-suite",
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("adjudicating scan: %v", err)
	}
	a, b := quiet.Findings.Findings(), loud.Findings.Findings()
	if len(a) != len(b) {
		t.Fatalf("adjudication changed the finding count: %d vs %d", len(a), len(b))
	}

	var disagreements int
	for i := range a {
		if a[i].Confidence != b[i].Confidence {
			t.Errorf("finding %d: adjudication rewrote the analyzer's confidence "+
				"%s -> %s", i, a[i].Confidence, b[i].Confidence)
		}
		if a[i].EvidenceConfidence != "" {
			t.Errorf("finding %d carries an evidence confidence on a scan that did not "+
				"adjudicate; absent and LOW are different statements", i)
		}
		if onAnalyzerScale(b[i].EvidenceConfidence) != b[i].Confidence {
			disagreements++
		}
	}
	// The two scales disagreeing is the normal case, not an error — it is what
	// the second field exists to show. If they ever agree everywhere, one of
	// them has stopped carrying information.
	if disagreements == 0 {
		t.Error("the analyzer and the evidence agree about every finding; one of the " +
			"two scales is no longer saying anything of its own")
	}
	t.Logf("%d of %d findings: the analyzer and the evidence disagree", disagreements, len(b))
}

// onAnalyzerScale maps the kernel's confidence onto the analyzer's three
// levels, which is the comparison the flip would have made.
func onAnalyzerScale(c string) findings.Confidence {
	switch evidence.Confidence(c) {
	case evidence.ConfidenceConfirmed, evidence.ConfidenceHigh:
		return findings.ConfidenceHigh
	case evidence.ConfidenceMedium:
		return findings.ConfidenceMedium
	default:
		return findings.ConfidenceLow
	}
}
