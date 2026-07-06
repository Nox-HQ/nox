package main

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// clojureSuitePath resolves the Clojure honest measurement corpus relative to the
// repo root. The CLI package lives in ./cli, so the corpus is one directory up.
func clojureSuitePath() string {
	return filepath.Join("..", "testdata", "precision-suite-clojure")
}

// TestPrecisionSuiteBaselineClojure is the ratchet for the Clojure corpus: it
// scans the honest measurement suite, loads the committed baseline snapshot, and
// fails if any gated metric regressed (precision/recall/F1 dropped, or FP /
// findings-per-issue rose).
//
// Clojure scores the LOWEST recall of any supported language, by design. It is a
// Lisp — prefix s-expressions `(fn arg …)`, `(let [x v] …)` — the furthest of any
// language from the assignment/call model the taint engine was built for, so the
// FORM recognizer catches only the idiomatic `(def x …)` / `(let [x …])` binding +
// `(callee args…)` call shapes. Threading macros (`->`, `->>`), `apply`, and other
// higher-order dispatch reorder or indirect the sink's argument position beyond
// what a positional recognizer can follow, so the suite carries honest false
// negatives (see testdata/precision-suite-clojure/README.md). Pinning the number
// here means Clojure PRECISION can no longer silently regress: a change that makes
// the suite noisier fails CI. When the suite legitimately improves, this test
// reports the improvement and tells you to refresh baseline.json.
func TestPrecisionSuiteBaselineClojure(t *testing.T) {
	dir := clojureSuitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("clojure suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("clojure suite regressed: %s", r.String())
		}
		t.Fatalf("clojure precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-clojure "+
			"--baseline testdata/precision-suite-clojure/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("clojure precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, recall %.3f->%.3f, FP %d->%d); "+
			"refresh testdata/precision-suite-clojure/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.Recall, current.Recall, base.FP, current.FP)
	}

	// Precision floor: the Clojure model must stay at or above the 0.90 gate CI
	// enforces via --min-precision, independent of the baseline ratchet. This is the
	// guardrail that keeps recall honesty from costing precision — a Lisp's
	// clean/validated forms (parameterized jdbc vector, Integer/parseInt) must not
	// FP even as the honest recall gap stays wide.
	if p := report.Overall.Precision(); p < 0.90 {
		t.Errorf("clojure suite precision %.3f is below the 0.90 floor:\n%s",
			p, renderPrecisionTable(dir, &report))
	}
}
