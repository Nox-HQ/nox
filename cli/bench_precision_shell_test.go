package main

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// shellSuitePath resolves the shell/bash honest measurement corpus relative to
// the repo root. The CLI package lives in ./cli, so the corpus is one directory
// up.
func shellSuitePath() string {
	return filepath.Join("..", "testdata", "precision-suite-shell")
}

// TestPrecisionSuiteBaselineShell is the ratchet for the shell corpus: it scans
// the honest measurement suite, loads the committed baseline snapshot, and fails
// if any gated metric regressed (precision/recall/F1 dropped, or FP /
// findings-per-issue rose).
//
// Shell's paren-less, word-splitting, dynamically-constructed command grammar is
// the hardest of any supported language for a flat per-line recognizer. The
// suite's last two false negatives — taint laundered through a `local`-declared
// variable — are now closed, so it scores 1.0 (see
// testdata/precision-suite-shell/README.md).
//
// That 1.0 means the corpus has stopped INDICTING anything, not that shell
// dataflow is solved; the README's open limits (word-splitting, arrays,
// pipeline-fed commands) are real and simply lack a failing sample. Pinning the
// number here means shell precision can no longer silently regress: a change
// that makes the suite noisier fails CI.
func TestPrecisionSuiteBaselineShell(t *testing.T) {
	dir := shellSuitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("shell suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("shell suite regressed: %s", r.String())
		}
		t.Fatalf("shell precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-shell "+
			"--baseline testdata/precision-suite-shell/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("shell precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, recall %.3f->%.3f, FP %d->%d); "+
			"refresh testdata/precision-suite-shell/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.Recall, current.Recall, base.FP, current.FP)
	}

	// Precision floor: the shell model must stay at or above the 0.90 gate CI
	// enforces via --min-precision, independent of the baseline ratchet. This is
	// the hard part for shell — quoted/validated scripts must not FP — so the
	// floor is the guardrail that keeps recall honesty from costing precision.
	if p := report.Overall.Precision(); p < 0.90 {
		t.Errorf("shell suite precision %.3f is below the 0.90 floor:\n%s",
			p, renderPrecisionTable(dir, &report))
	}
}
