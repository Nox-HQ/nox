package main

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// corpusPath resolves the shipped labeled corpus relative to the repo root.
// The CLI package lives in ./cli, so the corpus is one directory up.
func corpusPath() string {
	return filepath.Join("..", "testdata", "precision-corpus")
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
