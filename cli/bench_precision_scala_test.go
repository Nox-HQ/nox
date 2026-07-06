package main

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// scalaSuitePath resolves the Scala honest measurement corpus relative to the
// repo root. The CLI package lives in ./cli, so the corpus is one directory up.
func scalaSuitePath() string {
	return filepath.Join("..", "testdata", "precision-suite-scala")
}

// TestPrecisionSuiteBaselineScala is the ratchet for the Scala corpus: it scans
// the honest measurement suite, loads the committed baseline snapshot, and fails
// if any gated metric regressed (precision/recall/F1 dropped, or FP /
// findings-per-issue rose).
//
// Like the other honest suites (and unlike the curated precision-corpus, which
// demands a perfect 1.0), this suite measures nox's Scala taint model against
// ground truth so real recall gaps show up as a number. Pinning that number here
// means Scala precision can no longer silently regress: a change that makes the
// suite noisier fails CI. When the suite legitimately improves, this test reports
// the improvement and tells you to refresh baseline.json.
func TestPrecisionSuiteBaselineScala(t *testing.T) {
	dir := scalaSuitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("scala suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("scala suite regressed: %s", r.String())
		}
		t.Fatalf("scala precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-scala "+
			"--baseline testdata/precision-suite-scala/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("scala precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, recall %.3f->%.3f, FP %d->%d); "+
			"refresh testdata/precision-suite-scala/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.Recall, current.Recall, base.FP, current.FP)
	}

	// Precision floor: the Scala model must stay at or above the 0.90 gate CI
	// enforces via --min-precision, independent of the baseline ratchet.
	if p := report.Overall.Precision(); p < 0.90 {
		t.Errorf("scala suite precision %.3f is below the 0.90 floor:\n%s",
			p, renderPrecisionTable(dir, &report))
	}
}
