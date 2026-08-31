package core

import (
	"testing"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/migration"
)

func measureOn(t *testing.T, target string) migration.Report {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := RunScanWithOptions(target, ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan %s: %v", target, err)
	}
	return migration.Measure(res.Findings.Findings(), func(f findings.Finding) evidence.Ledger {
		return res.Reasoning.About(SubjectForFinding(f))
	})
}

// TestMigrationCoverageIsMeasuredNotAsserted is Track J's progress metric, and
// it exists because the ordering J asks for — families "according to observed
// value/risk, not alphabetically" — cannot be chosen from a list of rule counts
// or from intuition. The one intervention that moved a number was checksum
// verification; the one predicted to and did not was recording more heuristics.
//
// The report is logged rather than asserted against a target. A threshold here
// would be a number somebody picked, and the useful thing is the trend and the
// breakdown, read by a person deciding what to do next.
func TestMigrationCoverageIsMeasuredNotAsserted(t *testing.T) {
	for _, target := range []string{"..", "../testdata/precision-suite"} {
		r := measureOn(t, target)
		t.Logf("=== %s — %d findings, %d above heuristic, %d earned ===",
			target, r.Findings, r.AboveHeuristic, r.Earned)
		for _, f := range r.Families {
			note := ""
			switch {
			case f.Migrated():
				note = "migrated"
			case f.ClassifiedAbove():
				note = "classified above heuristic by rule prefix, not by evidence"
			default:
				note = "heuristic only"
			}
			t.Logf("  %-10s findings=%-4d corroborated=%-4d above=%-4d earned=%-4d strongest=%-22s %s",
				f.Family, f.Findings, f.Corroborated, f.AboveHeuristic, f.Earned, f.Strongest, note)
		}
	}
}

// TestEarnedEvidenceIsNotTheSameAsAGenerousClassification is the distinction
// the metric exists to keep.
//
// reasoning.ObservationKind hands TAINT and VULN findings KindStatic on the
// strength of their rule prefix. That is defensible — dataflow analysis and a
// version-range match are not pattern matches — but it is a classification
// decision, and a metric that counted it as migration would have shown those
// families finished on the day the switch was written, while a family that
// actually verified something scored the same.
func TestEarnedEvidenceIsNotTheSameAsAGenerousClassification(t *testing.T) {
	r := measureOn(t, "../testdata/precision-suite")

	var classified, migrated []string
	for _, f := range r.Families {
		switch {
		case f.ClassifiedAbove():
			classified = append(classified, f.Family)
		case f.Migrated():
			migrated = append(migrated, f.Family)
		}
	}
	if len(classified) == 0 {
		t.Error("no family is above heuristic purely by classification; either " +
			"ObservationKind stopped promoting TAINT and VULN, or this corpus " +
			"stopped exercising them — and the distinction this metric keeps has " +
			"become untestable either way")
	}
	if len(migrated) == 0 {
		t.Error("no family has earned an above-heuristic claim; checksum verification " +
			"was the one intervention measured to do this, so either it stopped " +
			"running or the corpus stopped exercising it")
	}
	t.Logf("earned: %v — classified only: %v", migrated, classified)
}

// TestBareObservationIsRecognised holds the string match in coverage.go to the
// statement the scan actually writes.
//
// The match is fragile in exactly one direction: if the wording changes, every
// observation looks like corroboration and the migration number improves
// without anything having been migrated. A metric that silently flatters the
// work is worse than no metric.
func TestBareObservationIsRecognised(t *testing.T) {
	// Test the recogniser directly, not through a proxy. An earlier version
	// asserted that no family is "corroborated everywhere with nothing earned",
	// on the theory that only a broken recogniser produces that shape. That
	// theory expired: once the AI analyzer records what it checked about
	// survivors (heuristic corroboration, nothing earned), a fully-corroborated
	// heuristic family is the NORMAL state, indistinguishable from a broken
	// recogniser under the proxy. So this checks the actual property — a
	// finding whose only claim is the bare observation is not counted as
	// corroborated — which is what the proxy was standing in for.
	obs := func(ruleID string) evidence.Claim {
		return evidence.Claim{
			Kind: evidence.KindHeuristic, Statement: "rule " + ruleID + " matched at this location",
		}
	}
	bare := findings.Finding{RuleID: "SEC-003", Fingerprint: "a"}
	extra := findings.Finding{RuleID: "SEC-003", Fingerprint: "b"}

	rep := migration.Measure([]findings.Finding{bare, extra}, func(f findings.Finding) evidence.Ledger {
		if f.Fingerprint == "a" {
			return evidence.Ledger{Claims: []evidence.Claim{obs("SEC-003")}}
		}
		return evidence.Ledger{Claims: []evidence.Claim{
			obs("SEC-003"),
			{Kind: evidence.KindHeuristic, Statement: "the value carries a recognised provider prefix"},
		}}
	})
	if len(rep.Families) != 1 {
		t.Fatalf("expected one family, got %d", len(rep.Families))
	}
	// Of the two findings, only the one with a claim BEYOND the observation is
	// corroborated. A recogniser that stopped matching the observation string
	// would count both.
	if rep.Families[0].Corroborated != 1 {
		t.Errorf("corroborated = %d, want 1; the bare-observation finding was counted "+
			"as corroborated, so isBareObservation has stopped matching the statement "+
			"the scan writes", rep.Families[0].Corroborated)
	}
}
