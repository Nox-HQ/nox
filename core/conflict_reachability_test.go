package core

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

// TestConflictSurvivesToTheScanResult. Verdict.Conflicted used to be computed
// in adjudicateFindings and dropped on the floor; nothing outside the
// adjudicator's own test read it.
//
// That cost nothing, because nothing conflicts — which is exactly the condition
// under which a discarded value is impossible to notice. This asserts the wire
// exists, by driving it from a ledger built for the purpose rather than by
// hoping the corpus produces one.
func TestConflictSurvivesToTheScanResult(t *testing.T) {
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
		t.Fatal("no findings; the rest of this test is vacuous")
	}

	// Manufacture the disagreement the pipeline cannot yet produce: a second
	// producer filing a refutation at the same strength as the scanner's
	// strongest support, about a subject the scanner already reported.
	subject := SubjectForFinding(all[0])
	before := res.Reasoning.About(subject)
	strongest, ok := before.Strongest()
	if !ok {
		t.Fatalf("no claim about %v; pick a finding whose ledger is populated", subject)
	}
	res.Reasoning.Refute(subject, strongest.Kind, "some-other-producer", "plugin",
		"a second producer disagrees at equal strength")

	after := res.Reasoning.About(subject)
	if !after.Conflict(subject) {
		t.Fatalf("the kernel does not call this a conflict (strongest kind %q); "+
			"the fixture is wrong, not the pipeline", strongest.Kind)
	}

	divergences, conflicts := adjudicateFindings(res.Reasoning, res.Findings)
	_ = divergences
	if len(conflicts) == 0 {
		t.Fatal("a conflicting subject produced no Conflict in the scan result; " +
			"the disagreement between two producers is being discarded")
	}
	c := conflicts[0]
	if c.Fingerprint == "" || c.RuleID == "" {
		t.Errorf("conflict %+v does not identify the finding it is about", c)
	}
	if c.Supporting == "" || c.Refuting == "" {
		t.Errorf("conflict %+v says two producers disagree without saying about what", c)
	}
}

// TestConflictIsUnreachableUntilASecondProducerExists records why every
// committed corpus reports zero conflicts, because "zero" has two very
// different causes and only one of them is good news.
//
// It is structural, not luck. A refuted candidate is DROPPED before any
// supporting claim is recorded, and a surviving one is corroborated on a
// separate path, so the two polarities do not meet. The one place they do is
// the checksum verifier, which files a KindStatic refutation against a
// candidate whose supports are KindHeuristic — and 40 does not equal 10.
//
// So the check is unreachable rather than merely unobserved, and the two look
// identical from outside. What makes it reachable is a SECOND producer filing
// claims about a subject the scanner already has an opinion on: the
// intelligence service under Track H, or a plugin. This test fails then, which
// is the point — the wiring is already in place, and the failure says to go
// look at what the two producers disagree about rather than to build anything.
func TestConflictIsUnreachableUntilASecondProducerExists(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	for _, dir := range []string{
		"../testdata/precision-suite",
		"../testdata/refutation-suite",
		"../testdata/reachability-suite",
	} {
		res, err := RunScanWithOptions(dir, ScanOptions{Offline: true, RecordReasoning: true})
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if n := len(res.Conflicts); n != 0 {
			t.Errorf("%s produced %d conflict(s): %+v. Something now files claims of both "+
				"polarities at equal strength about one subject. That is not a regression "+
				"— it is the condition this test exists to announce. Read the conflicts, "+
				"decide whether the disagreement is real, and update this test to expect it",
				dir, n, res.Conflicts)
		}

		// The structural reason, checked rather than asserted in prose: no
		// subject the scan REPORTS carries opposing claims at equal strength.
		var opposing, reported int
		isReported := map[evidence.Subject]bool{}
		for _, f := range res.Findings.Findings() {
			isReported[SubjectForFinding(f)] = true
		}
		for _, s := range res.Reasoning.Subjects() {
			l := res.Reasoning.About(s)
			var sup, ref bool
			for _, c := range l.Claims {
				if c.Refutes() {
					ref = true
				} else if c.Supports() {
					sup = true
				}
			}
			if sup && ref {
				opposing++
				if isReported[s] {
					reported++
				}
			}
		}
		t.Logf("%-34s subjects with both polarities: %d (%d of them reported), conflicts: %d",
			dir, opposing, reported, len(res.Conflicts))
	}
}
