package main

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// perlSuitePath resolves the Perl honest measurement corpus relative to the repo
// root. The CLI package lives in ./cli, so the corpus is one directory up.
func perlSuitePath() string {
	return filepath.Join("..", "testdata", "precision-suite-perl")
}

// TestPrecisionSuiteBaselinePerl is the ratchet for the Perl corpus: it scans the
// honest measurement suite, loads the committed baseline snapshot, and fails if
// any gated metric regressed (precision/recall/F1 dropped, or FP /
// findings-per-issue rose).
//
// Unlike the curated precision-corpus (which demands a perfect 1.0), this suite
// deliberately scores below 1.0 on recall — it measures nox's Perl taint model
// against ground truth so real recall gaps show up as a number. Perl is
// recognized pragmatically (no interpreter), so recall is expected to be moderate;
// pinning that number here means Perl precision can no longer silently regress.
func TestPrecisionSuiteBaselinePerl(t *testing.T) {
	dir := perlSuitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("perl suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("perl suite regressed: %s", r.String())
		}
		t.Fatalf("perl precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-perl "+
			"--baseline testdata/precision-suite-perl/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("perl precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, recall %.3f->%.3f, FP %d->%d); "+
			"refresh testdata/precision-suite-perl/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.Recall, current.Recall, base.FP, current.FP)
	}

	// Precision floor: the Perl model must stay at or above the 0.90 gate CI
	// enforces via --min-precision, independent of the baseline ratchet.
	if p := report.Overall.Precision(); p < 0.90 {
		t.Errorf("perl suite precision %.3f is below the 0.90 floor:\n%s",
			p, renderPrecisionTable(dir, &report))
	}
}
