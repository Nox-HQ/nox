package main

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// cppSuitePath resolves the C/C++ honest measurement corpus relative to the repo
// root. The CLI package lives in ./cli, so the corpus is one directory up.
func cppSuitePath() string {
	return filepath.Join("..", "testdata", "precision-suite-cpp")
}

// TestPrecisionSuiteBaselineCPP is the ratchet for the C/C++ corpus: it scans the
// honest measurement suite, loads the committed baseline snapshot, and fails if
// any gated metric regressed (precision/recall/F1 dropped, or FP /
// findings-per-issue rose).
//
// Like the other language suites (and unlike the curated precision-corpus, which
// demands a perfect 1.0), this suite deliberately scores below 1.0 on recall — it
// measures nox's C/C++ taint model against ground truth so real recall gaps (the
// std::ifstream constructor-init path-traversal FN documented in the suite
// README) show up as a number. Pinning that number here means C/C++ precision can
// no longer silently regress: a change that makes the suite noisier fails CI.
func TestPrecisionSuiteBaselineCPP(t *testing.T) {
	dir := cppSuitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("cpp suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("cpp suite regressed: %s", r.String())
		}
		t.Fatalf("cpp precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-cpp "+
			"--baseline testdata/precision-suite-cpp/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("cpp precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, recall %.3f->%.3f, FP %d->%d); "+
			"refresh testdata/precision-suite-cpp/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.Recall, current.Recall, base.FP, current.FP)
	}

	// Precision floor: the C/C++ model must stay at or above the 0.90 gate CI
	// enforces via --min-precision, independent of the baseline ratchet.
	if p := report.Overall.Precision(); p < 0.90 {
		t.Errorf("cpp suite precision %.3f is below the 0.90 floor:\n%s",
			p, renderPrecisionTable(dir, &report))
	}
}
