package main

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// luaSuitePath resolves the Lua honest measurement corpus relative to the repo
// root. The CLI package lives in ./cli, so the corpus is one directory up.
func luaSuitePath() string {
	return filepath.Join("..", "testdata", "precision-suite-lua")
}

// TestPrecisionSuiteBaselineLua is the ratchet for the Lua corpus: it scans the
// honest measurement suite, loads the committed baseline snapshot, and fails if
// any gated metric regressed (precision/recall/F1 dropped, or FP /
// findings-per-issue rose).
//
// The Lua model is the flat line/statement recognizer (lexctx scan_lua + engine
// extract_lua + the catalog `lua` block), sharing the recognizer's documented
// intraprocedural/straight-line limits (see testdata/precision-suite-lua/
// README.md). Pinning the number here means Lua PRECISION can no longer silently
// regress: a change that makes the suite noisier fails CI. When the suite
// legitimately improves, this test reports the improvement and tells you to
// refresh baseline.json.
func TestPrecisionSuiteBaselineLua(t *testing.T) {
	dir := luaSuitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("lua suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("lua suite regressed: %s", r.String())
		}
		t.Fatalf("lua precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-lua "+
			"--baseline testdata/precision-suite-lua/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("lua precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, recall %.3f->%.3f, FP %d->%d); "+
			"refresh testdata/precision-suite-lua/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.Recall, current.Recall, base.FP, current.FP)
	}

	// Precision floor: the Lua model must stay at or above the 0.90 gate CI
	// enforces via --min-precision, independent of the baseline ratchet.
	if p := report.Overall.Precision(); p < 0.90 {
		t.Errorf("lua suite precision %.3f is below the 0.90 floor:\n%s",
			p, renderPrecisionTable(dir, &report))
	}
}
