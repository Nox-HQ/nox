package main

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// elixirSuitePath resolves the Elixir honest measurement corpus relative to the
// repo root. The CLI package lives in ./cli, so the corpus is one directory up.
func elixirSuitePath() string {
	return filepath.Join("..", "testdata", "precision-suite-elixir")
}

// TestPrecisionSuiteBaselineElixir is the ratchet for the Elixir corpus: it scans
// the honest measurement suite, loads the committed baseline snapshot, and fails
// if any gated metric regressed (precision/recall/F1 dropped, or FP /
// findings-per-issue rose).
//
// Elixir recall is intentionally below 1.0 — of its two dominant dataflow
// idioms, the pipe operator `|>` is now followed to the end of the chain, but
// pattern matching is still more than a flat per-line recognizer can follow, so
// the suite carries one documented honest false negative (a destructuring
// pattern match; see testdata/precision-suite-elixir/README.md). Pinning the
// number here means
// Elixir PRECISION can no longer silently regress: a change that makes the suite
// noisier fails CI. When the suite legitimately improves, this test reports the
// improvement and tells you to refresh baseline.json.
func TestPrecisionSuiteBaselineElixir(t *testing.T) {
	dir := elixirSuitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("elixir suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("elixir suite regressed: %s", r.String())
		}
		t.Fatalf("elixir precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-elixir "+
			"--baseline testdata/precision-suite-elixir/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("elixir precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, recall %.3f->%.3f, FP %d->%d); "+
			"refresh testdata/precision-suite-elixir/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.Recall, current.Recall, base.FP, current.FP)
	}

	// Precision floor: the Elixir model must stay at or above the 0.90 gate CI
	// enforces via --min-precision, independent of the baseline ratchet. Recall is
	// honestly below 1.0 (pipe/pattern-match gaps), so the floor is the guardrail
	// that keeps recall honesty from ever costing precision.
	if p := report.Overall.Precision(); p < 0.90 {
		t.Errorf("elixir suite precision %.3f is below the 0.90 floor:\n%s",
			p, renderPrecisionTable(dir, &report))
	}
}
