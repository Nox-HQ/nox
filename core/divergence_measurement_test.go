package core

import (
	"path/filepath"
	"testing"
)

// The divergence measurement, kept executable.
//
// It was not, and it went stale exactly as you would expect. "15 of 37 findings
// diverge, all over-claimed" was measured on 2026-08-30, quoted in four
// documents and a doc comment, and carried forward unchanged through three
// merged PRs that changed IaC output. By the time anything re-ran it the count
// had moved and the "all over-claimed" half had stopped being true — a claim
// about a measurement is worth what the last run of it was worth.
//
// So the numbers live here, and this test is deliberately brittle. A rule
// change that moves them fails it, and the failure says to re-measure and
// update the documents rather than to adjust the constant. That is the whole
// point: silent staleness is the failure mode, and a test nobody has to notice
// is the only defence against it.
//
// Re-measured 2026-09-07 at the head of the Phase 2.2 branch.
var divergenceBaseline = map[string]struct {
	findings, over, under int
}{
	"precision-suite":  {53, 16, 1},
	"precision-corpus": {5, 5, 0},
	"refutation-suite": {37, 5, 14},
}

func TestDivergenceShapeIsMeasuredNotRemembered(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scans; skipped in -short")
	}
	for corpus, want := range divergenceBaseline {
		t.Run(corpus, func(t *testing.T) {
			res, err := RunScanWithOptions(filepath.Join("..", "testdata", corpus),
				ScanOptions{Offline: true, RecordReasoning: true})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			var over, under int
			for _, d := range res.Divergences {
				if d.Overclaimed {
					over++
				} else {
					under++
				}
			}
			got := len(res.Findings.Findings())
			if got != want.findings || over != want.over || under != want.under {
				t.Errorf("findings=%d over-claimed=%d under-claimed=%d; recorded %d/%d/%d.\n"+
					"Re-measure and update the documents that quote these numbers — "+
					"core/adjudicate/adjudicate.go, docs/design/evidence-native-nox.md, "+
					"docs/design/phase-execution-plan.md, docs/backlog.md — rather than "+
					"editing the constant to match. A number nobody re-derived is the "+
					"failure this test exists to stop.",
					got, over, under, want.findings, want.over, want.under)
			}
			t.Logf("%s: %d findings, %d diverge (%d over-claimed, %d under-claimed)",
				corpus, got, over+under, over, under)
		})
	}
}

// Divergence must exist in BOTH directions, and the reason to assert it is that
// the record said otherwise for a month.
//
// "Every divergence is the analyzer claiming more than the evidence supports"
// shaped how Phase 4.1 was planned: if the only move is downward, promotion is
// a matter of deciding how much to demote. It is not. IaC rules author LOW and
// their static evidence aggregates to MEDIUM, so the adjudicator would raise
// them — and a flip that only knows how to lower confidence would either miss
// those or quietly hold them down.
func TestDivergenceRunsInBothDirections(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := RunScanWithOptions(filepath.Join("..", "testdata", "refutation-suite"),
		ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var over, under int
	for _, d := range res.Divergences {
		if d.Overclaimed {
			over++
		} else {
			under++
		}
	}
	if over == 0 || under == 0 {
		t.Errorf("divergences run in one direction only (over=%d under=%d). If that is now "+
			"true, Phase 4.1's plan changes with it — re-read the note in "+
			"core/adjudicate/adjudicate.go before treating a one-directional flip as safe.",
			over, under)
	}
}
