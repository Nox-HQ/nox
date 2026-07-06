package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// corpusPath resolves the shipped labeled corpus relative to the repo root.
// The CLI package lives in ./cli, so the corpus is one directory up.
func corpusPath() string {
	return filepath.Join("..", "testdata", "precision-corpus")
}

// suitePath resolves the honest measurement corpus (the one with real FPs/FNs)
// relative to the repo root.
func suitePath() string {
	return filepath.Join("..", "testdata", "precision-suite")
}

// suitePathPHP resolves the PHP honest measurement corpus relative to the repo
// root. It is a separate directory so the PHP taint model is measured against
// PHP-only ground truth, gated by its own baseline.
func suitePathPHP() string {
	return filepath.Join("..", "testdata", "precision-suite-php")
}

// suiteJavaPath resolves the Java-only honest measurement corpus relative to the
// repo root. It lives in its own directory so the Java taint samples and their
// baseline gate independently of the Python/JS/Go suite.
func suiteJavaPath() string {
	return filepath.Join("..", "testdata", "precision-suite-java")
}

// csharpSuitePath resolves the C#-specific honest measurement corpus.
func csharpSuitePath() string {
	return filepath.Join("..", "testdata", "precision-suite-csharp")
}

// TestPrecisionCorpusBaseline is a guard test: the shipped corpus is curated to
// score a perfect 1.0/1.0/1.0. If a rule change makes nox miss a labeled
// finding (recall drops) or fire on a clean sample (precision drops), this test
// fails and forces the corpus or the rule to be reconciled — which is exactly
// the regression signal the harness exists to provide.
func TestPrecisionCorpusBaseline(t *testing.T) {
	dir := corpusPath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("corpus has no expectations; a labeled corpus must declare some")
	}

	scanFindings, err := scanCorpusFindings(dir)
	if err != nil {
		t.Fatalf("scanCorpusFindings(%s): %v", dir, err)
	}

	report := bench.Score(scanFindings, expectations)

	if report.Overall.FP != 0 {
		t.Errorf("shipped corpus produced %d false positive(s); precision baseline broken:\n%s",
			report.Overall.FP, renderPrecisionTable(dir, &report))
	}
	if report.Overall.FN != 0 {
		t.Errorf("shipped corpus produced %d false negative(s); recall baseline broken:\n%s",
			report.Overall.FN, renderPrecisionTable(dir, &report))
	}
	if report.Overall.TP == 0 {
		t.Error("shipped corpus produced zero true positives; the samples no longer fire")
	}
}

// TestPrecisionSuiteBaseline is the ratchet: it scans the honest measurement
// suite, loads the committed baseline snapshot, and fails if any gated metric
// regressed (precision/recall/F1 dropped, or FP / findings-per-issue rose).
//
// Unlike TestPrecisionCorpusBaseline (which demands a perfect 1.0 on a curated
// fixture), this suite deliberately scores below 1.0 — it measures nox against
// ground truth so real over-firing and recall gaps show up as a number. Pinning
// that number here means precision can no longer silently regress: a rule change
// that makes the suite noisier fails CI. When the suite legitimately improves,
// this test reports the improvement and tells you to refresh baseline.json.
func TestPrecisionSuiteBaseline(t *testing.T) {
	dir := suitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("suite regressed: %s", r.String())
		}
		t.Fatalf("precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite "+
			"--baseline testdata/precision-suite/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, FP %d->%d, findings/issue %.2f->%.2f); "+
			"refresh testdata/precision-suite/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.FP, current.FP,
			base.FindingsPerIssue, current.FindingsPerIssue)
	}
}

// TestPrecisionSuiteBaselinePHP is the PHP ratchet: it scans the PHP honest
// measurement suite, loads its committed baseline snapshot, and fails if any
// gated metric regressed (precision/recall/F1 dropped, or FP / findings-per-issue
// rose). It mirrors TestPrecisionSuiteBaseline but pins the PHP taint model's
// numbers against PHP-only ground truth, so a change that makes PHP scanning
// noisier or misses a PHP flow fails CI independently of the other languages.
func TestPrecisionSuiteBaselinePHP(t *testing.T) {
	dir := suitePathPHP()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("PHP suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("PHP suite regressed: %s", r.String())
		}
		t.Fatalf("PHP precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-php "+
			"--baseline testdata/precision-suite-php/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("PHP precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, FP %d->%d, findings/issue %.2f->%.2f); "+
			"refresh testdata/precision-suite-php/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.FP, current.FP,
			base.FindingsPerIssue, current.FindingsPerIssue)
	}
}

// TestPrecisionSuiteBaselineJava is the Java-suite ratchet: it scans the
// Java-only honest measurement corpus, loads its committed baseline snapshot, and
// fails if any gated metric regressed. It mirrors TestPrecisionSuiteBaseline for
// the dedicated Java corpus, so a change to the Java lexer, extractor, or catalog
// that makes the suite noisier (or drops a true positive) fails CI. When the Java
// suite legitimately improves, this test reports it and tells you to refresh
// testdata/precision-suite-java/baseline.json.
func TestPrecisionSuiteBaselineJava(t *testing.T) {
	dir := suiteJavaPath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("Java suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("Java suite regressed: %s", r.String())
		}
		t.Fatalf("Java precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-java "+
			"--baseline testdata/precision-suite-java/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("Java precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, FP %d->%d, findings/issue %.2f->%.2f); "+
			"refresh testdata/precision-suite-java/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.FP, current.FP,
			base.FindingsPerIssue, current.FindingsPerIssue)
	}
}

// suitePathRust resolves the honest Rust measurement corpus relative to the
// repo root (the CLI package lives in ./cli, so testdata is one dir up).
func suitePathRust() string {
	return filepath.Join("..", "testdata", "precision-suite-rust")
}

// TestPrecisionSuiteBaselineRust is the ratchet for the Rust corpus, mirroring
// TestPrecisionSuiteBaseline: it scans the Rust suite, loads the committed
// baseline snapshot, and fails if any gated metric regressed. The Rust suite
// deliberately scores below 1.0 on recall (an honest, documented web-extractor
// false negative — see testdata/precision-suite-rust/README.md); pinning that
// number here means Rust precision can no longer silently regress and the known
// FN cannot be quietly hidden.
func TestPrecisionSuiteBaselineRust(t *testing.T) {
	dir := suitePathRust()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("rust suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("rust suite regressed: %s", r.String())
		}
		t.Fatalf("rust precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-rust "+
			"--baseline testdata/precision-suite-rust/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	// Precision must never fall below the CI gate floor (0.90) for the Rust suite.
	if report.Overall.Precision() < 0.90 {
		t.Errorf("rust suite precision %.3f < 0.90 floor:\n%s",
			report.Overall.Precision(), renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("rust precision suite IMPROVED vs baseline.json (precision %.3f->%.3f, recall %.3f->%.3f); "+
			"refresh testdata/precision-suite-rust/baseline.json to lock in the gain",
			base.Precision, current.Precision, base.Recall, current.Recall)
	}
}

// TestPrecisionSuiteBaselineCSharp is the C# ratchet: it scans the C# honest
// measurement suite, loads its committed baseline snapshot, and fails if any
// gated metric regressed. It is the analog of TestPrecisionSuiteBaseline for the
// C# language block (lexctx scan_csharp + engine extract_csharp + the catalog
// `csharp` sinks), so a change that makes C# taint analysis noisier or miss a
// labeled flow fails CI. When the suite legitimately improves it reports the gain
// and tells you to refresh baseline.json.
func TestPrecisionSuiteBaselineCSharp(t *testing.T) {
	dir := csharpSuitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("C# suite has no expectations; a labeled corpus must declare some")
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
			t.Errorf("C# suite regressed: %s", r.String())
		}
		t.Fatalf("C# precision suite regressed vs baseline.json; investigate the change or, if intended, "+
			"regenerate the snapshot with `nox bench --precision testdata/precision-suite-csharp "+
			"--baseline testdata/precision-suite-csharp/baseline.json` after deleting it.\n%s",
			renderPrecisionTable(dir, &report))
	}

	// This corpus is engineered to score a clean 1.0/1.0: every clean stressor
	// must stay silent and every annotated flow must fire. Assert that directly so
	// a precision or recall break is unmissable, not just a baseline drift.
	if report.Overall.FP != 0 {
		t.Errorf("C# suite produced %d false positive(s); precision broken:\n%s",
			report.Overall.FP, renderPrecisionTable(dir, &report))
	}
	if report.Overall.FN != 0 {
		t.Errorf("C# suite produced %d false negative(s); recall broken:\n%s",
			report.Overall.FN, renderPrecisionTable(dir, &report))
	}

	if bench.Improved(base, current) {
		t.Logf("C# precision suite IMPROVED vs baseline.json; refresh "+
			"testdata/precision-suite-csharp/baseline.json to lock in the gain (precision %.3f->%.3f, FP %d->%d)",
			base.Precision, current.Precision, base.FP, current.FP)
	}
}

// TestBaselineGateFlow exercises the write -> compare -> regress lifecycle of
// the --baseline gate against the curated corpus (whose score is stable at
// 1.0). First run bootstraps the snapshot and passes; a re-run against the
// unchanged snapshot passes; a tampered snapshot demanding a lower FP than the
// corpus can deliver forces a regression exit.
func TestBaselineGateFlow(t *testing.T) {
	dir := corpusPath()
	baseline := filepath.Join(t.TempDir(), "baseline.json")

	// Absent -> written, exit 0.
	if got := run([]string{"bench", "--precision", dir, "--baseline", baseline}); got != 0 {
		t.Fatalf("first run (write baseline) = %d, want 0", got)
	}
	if _, err := os.Stat(baseline); err != nil {
		t.Fatalf("baseline was not written: %v", err)
	}

	// Present and matching -> exit 0.
	if got := run([]string{"bench", "--precision", dir, "--baseline", baseline}); got != 0 {
		t.Fatalf("second run (matching baseline) = %d, want 0", got)
	}

	// Tamper: demand precision higher than the corpus can now deliver so the
	// gate must fail.
	tampered := bench.Baseline{Precision: 1.0, Recall: 1.0, F1: 1.0, FP: -1, FindingsPerIssue: 0}
	data, err := json.MarshalIndent(tampered, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered baseline: %v", err)
	}
	if err := os.WriteFile(baseline, data, 0o600); err != nil {
		t.Fatalf("write tampered baseline: %v", err)
	}
	if got := run([]string{"bench", "--precision", dir, "--baseline", baseline}); got != 1 {
		t.Fatalf("third run (regressed baseline) = %d, want 1", got)
	}
}

// loadBaseline reads and parses a committed baseline snapshot for a test.
func loadBaseline(t *testing.T, path string) bench.Baseline {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("reading baseline %s: %v", path, err)
	}
	var b bench.Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("parsing baseline %s: %v", path, err)
	}
	return b
}

// TestRunBenchPrecisionExitCodes exercises the CLI entry point end to end,
// including the --min-precision gate.
func TestRunBenchPrecisionExitCodes(t *testing.T) {
	dir := corpusPath()

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"table mode succeeds", []string{"bench", "--precision", dir}, 0},
		{"json mode succeeds", []string{"bench", "--precision", dir, "--json"}, 0},
		{"positional corpus arg", []string{"bench", "--precision=" + dir}, 0},
		{"gate passes at achievable threshold", []string{"bench", "--precision", dir, "--min-precision", "0.9"}, 0},
		{"gate fails at impossible threshold", []string{"bench", "--precision", dir, "--min-precision", "1.1"}, 1},
		{"missing corpus errors", []string{"bench", "--precision", filepath.Join(t.TempDir(), "nope")}, 2},
		{"baseline absent is written and passes", []string{"bench", "--precision", dir, "--baseline", filepath.Join(t.TempDir(), "b.json")}, 0},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := run(tt.args); got != tt.want {
				t.Errorf("run(%v) = %d, want %d", tt.args, got, tt.want)
			}
		})
	}
}
