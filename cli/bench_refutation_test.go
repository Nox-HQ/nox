package main

import (
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// refutationSuitePath resolves the refutation corpus relative to the repo root.
func refutationSuitePath() string {
	return filepath.Join("..", "testdata", "refutation-suite")
}

// TestRefutationSuiteRecall is the programme's recall ratchet, and it is the
// one guard test whose threshold is not negotiable.
//
// Every other precision test in this package protects against nox reporting
// too much. This one protects against the opposite failure, which is the one
// the evidence-native architecture introduces: refinement, refutation,
// reachability and structural deduplication all exist to REMOVE findings, and
// a scanner that removes the wrong ones looks better on every metric anyone
// routinely watches. Precision rises. Finding counts fall. The corpus that
// measures over-firing reports an improvement. Nothing anywhere goes red.
//
// So the refutation corpus inverts the ground truth. Each sample carries a
// REAL vulnerability shaped so that a plausible refiner would wrongly dismiss
// it — a sink whose argument holds a comment character, a hand-written file
// containing a generated-code banner as data, a sanitizer applied to the
// neighbouring variable, one tainted value reaching two different sinks. There
// are no clean samples and there is nothing to tune: recall is 1.000 today and
// any drop means a refinement has hidden a real vulnerability.
//
// Nothing that changes scan output ships while this test is failing. If a
// change makes a sample here genuinely wrong, fix or replace the SAMPLE and
// say why in the commit — never lower the threshold, and never delete a case
// to make a refiner pass. See docs/design/evidence-native-nox.md, Gate A.
func TestRefutationSuiteRecall(t *testing.T) {
	dir := refutationSuitePath()

	expectations, err := bench.ParseCorpus(dir)
	if err != nil {
		t.Fatalf("ParseCorpus(%s): %v", dir, err)
	}
	if len(expectations) == 0 {
		t.Fatal("refutation suite declares no expectations; the corpus cannot protect anything")
	}

	scanFindings, err := scanCorpusFindings(dir)
	if err != nil {
		t.Fatalf("scanCorpusFindings(%s): %v", dir, err)
	}

	report := bench.Score(scanFindings, expectations)

	if report.Overall.FN != 0 {
		t.Errorf("GATE A FAILED: %d real vulnerability/vulnerabilities in the refutation suite "+
			"are no longer reported. A refinement is suppressing something real — this is the "+
			"failure mode the corpus exists to catch, and it does not show up as a regression "+
			"anywhere else.\n%s",
			report.Overall.FN, renderPrecisionTable(dir, &report))
	}

	if got := report.Overall.Recall(); got != 1.0 {
		t.Errorf("refutation suite recall = %.3f, want exactly 1.000", got)
	}

	// Not the corpus's purpose, but a false positive here would mean a sample
	// fires somewhere it was never meant to, which makes the recall number
	// harder to read. Catch it while it is one finding rather than ten.
	if report.Overall.FP != 0 {
		t.Errorf("refutation suite produced %d false positive(s); a sample is firing off its "+
			"annotated line and should be tightened:\n%s",
			report.Overall.FP, renderPrecisionTable(dir, &report))
	}
}
