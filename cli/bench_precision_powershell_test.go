package main

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// powershellSuitePath resolves the PowerShell honest measurement corpus relative
// to the repo root. The CLI package lives in ./cli, so the corpus is one
// directory up. It lives in its own directory so the PowerShell taint samples and
// their baseline gate independently of the other languages.
func powershellSuitePath() string {
	return filepath.Join("..", "testdata", "precision-suite-powershell")
}

// TestPrecisionSuiteBaselinePowerShell is the ratchet for the PowerShell corpus,
// mirroring TestPrecisionSuiteBaseline: it scans the PowerShell suite, loads the
// committed baseline snapshot, and fails if any gated metric regressed
// (precision/recall/F1 dropped, or FP / findings-per-issue rose).
//
// The suite now scores 1.0 across the board: its last honest false negative,
// pipeline dataflow (`$x | Invoke-Expression`, `tp_pipeline_fn.ps1`), was closed
// by folding pipeline stages into nested positional calls. Pinning that here
// means the flow cannot silently stop being detected, and the precision floor
// (0.90) is asserted directly so no new PowerShell false positive can creep in.
//
// A suite at 1.0 has stopped indicting anything, so it no longer measures the
// recognizer's real limits — see the README's still-open list (splatting,
// receiver typing). Adding a sample that FAILS is what keeps this honest.
func TestPrecisionSuiteBaselinePowerShell(t *testing.T) {
	dir := powershellSuitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("powershell suite has no expectations; a labeled corpus must declare some")
	}

	scanFindings, err := scanCorpusFindings(dir)
	if err != nil {
		t.Fatalf("scanCorpusFindings(%s): %v", dir, err)
	}

	report := bench.Score(scanFindings, expectations)
	current := bench.BaselineFromReport(&report)

	base := loadBaseline(t, filepath.Join(dir, "baseline.json"))

	if regressions := bench.CompareBaseline(base, current); len(regressions) > 0 {
		for _, r := range regressions {
			t.Errorf("powershell suite regressed: %s", r.String())
		}
		t.Fatalf("powershell precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-powershell "+
			"--baseline testdata/precision-suite-powershell/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	// Precision must never fall below the CI gate floor (0.90) for the PowerShell
	// suite, independent of the baseline ratchet.
	if p := report.Overall.Precision(); p < 0.90 {
		t.Errorf("powershell suite precision %.3f is below the 0.90 floor:\n%s",
			p, renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("powershell precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, recall %.3f->%.3f, FP %d->%d); "+
			"refresh testdata/precision-suite-powershell/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.Recall, current.Recall, base.FP, current.FP)
	}
}
