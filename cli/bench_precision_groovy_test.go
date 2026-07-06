package main

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// groovySuitePath resolves the Groovy honest measurement corpus relative to the
// repo root. The CLI package lives in ./cli, so the corpus is one directory up.
func groovySuitePath() string {
	return filepath.Join("..", "testdata", "precision-suite-groovy")
}

// TestPrecisionSuiteBaselineGroovy is the ratchet for the Groovy corpus: it scans
// the honest measurement suite, loads the committed baseline snapshot, and fails
// if any gated metric regressed (precision/recall/F1 dropped, or FP /
// findings-per-issue rose).
//
// Unlike the curated precision-corpus (which demands a perfect 1.0), this suite
// deliberately scores below 1.0 on recall — it measures nox's Groovy taint model
// against ground truth so real recall gaps (the closure false negative) show up as
// a number. Pinning that number here means Groovy precision can no longer silently
// regress: a change that makes the suite noisier fails CI. When the suite
// legitimately improves, this test reports the improvement and tells you to refresh
// baseline.json.
func TestPrecisionSuiteBaselineGroovy(t *testing.T) {
	dir := groovySuitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("groovy suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("groovy suite regressed: %s", r.String())
		}
		t.Fatalf("groovy precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-groovy "+
			"--baseline testdata/precision-suite-groovy/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("groovy precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, recall %.3f->%.3f, FP %d->%d); "+
			"refresh testdata/precision-suite-groovy/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.Recall, current.Recall, base.FP, current.FP)
	}

	// Precision floor: the Groovy model must stay at or above the 0.90 gate CI
	// enforces via --min-precision, independent of the baseline ratchet.
	if p := report.Overall.Precision(); p < 0.90 {
		t.Errorf("groovy suite precision %.3f is below the 0.90 floor:\n%s",
			p, renderPrecisionTable(dir, &report))
	}
}
