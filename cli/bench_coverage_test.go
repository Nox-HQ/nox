package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// TestRefutationBranchCoverage is Gate A's second half.
//
// TestRefutationSuiteRecall answers "does every fixture still fire?". It
// cannot answer "is there still a fixture?" — deleting the last sample for a
// refutation branch takes its expectations with it, so recall stays 1.000 over
// whatever remains and the branch quietly stops being guarded. That is the
// empty-set success this programme exists to remove: a check over nothing
// passes, and passes identically to a check that found nothing wrong.
//
// The fix is to declare the universe somewhere a testdata deletion cannot
// reach. bench.RefutationBranches lists every way nox can decide a candidate
// is not a finding; each fixture claims one with a `nox-cover` annotation.
// Removing the only fixture for a branch leaves the branch registered and
// unwitnessed, and this test fails naming it.
//
// Adding the branch before the fixture is the intended order: the failing test
// is the specification for the sample that has to be written.
func TestRefutationBranchCoverage(t *testing.T) {
	root := filepath.Join("..", "testdata")

	report, err := bench.CheckCoverage(root, bench.RefutationBranches)
	if err != nil {
		t.Fatalf("CheckCoverage: %v", err)
	}

	for _, b := range report.Uncovered {
		t.Errorf("GATE A COVERAGE: refutation branch %q has no fixture in testdata/%s.\n"+
			"  proposition: %s\n"+
			"  wrong reasoning it must catch: %s\n"+
			"Either write the sample, or delete the branch from bench.RefutationBranches "+
			"and say in the commit why nox no longer refutes this way.",
			b.ID, b.Corpus, b.Proposition, b.Wrong)
	}
	for _, c := range report.Unknown {
		t.Errorf("%s:%d claims unregistered branch %q; register it in bench.RefutationBranches "+
			"or fix the typo — an unregistered claim guards nothing",
			c.FilePath, c.Line, c.BranchID)
	}
	for _, c := range report.Misfiled {
		t.Errorf("%s:%d claims branch %q, which declares a different corpus; a fixture in the "+
			"wrong corpus is scored by the wrong guard", c.FilePath, c.Line, c.BranchID)
	}
}

// TestRefutationBranchesAreWellFormed pins the registry's own invariants.
//
// A registry entry with an empty proposition or an empty Wrong is a branch
// nobody can review: the coverage failure it produces would name an ID and say
// nothing about what deleting the fixture would cost.
func TestRefutationBranchesAreWellFormed(t *testing.T) {
	if len(bench.RefutationBranches) == 0 {
		t.Fatal("the branch registry is empty; every coverage check over it passes vacuously")
	}
	seen := map[string]bool{}
	for _, b := range bench.RefutationBranches {
		switch {
		case b.ID == "":
			t.Errorf("branch %+v has no ID", b)
		case seen[b.ID]:
			t.Errorf("duplicate branch ID %q", b.ID)
		}
		seen[b.ID] = true
		if strings.TrimSpace(b.Wrong) == "" {
			t.Errorf("branch %q does not say what wrong reasoning it catches", b.ID)
		}
		if strings.TrimSpace(b.Proposition) == "" {
			t.Errorf("branch %q does not say what its refutation establishes", b.ID)
		}
		if strings.TrimSpace(b.Family) == "" || strings.TrimSpace(b.Matcher) == "" {
			t.Errorf("branch %q must name a rule family and an evaluation path", b.ID)
		}
	}
}

// TestCoverageCheckFailsWhenAFixtureIsRemoved is the falsification.
//
// Every guard in this repo has been written correctly against the wrong input
// at least once, so the coverage check is asked to fail on demand: a registry
// naming a branch no fixture claims must be reported, by name. Without this,
// a CheckCoverage that silently returned an empty report would pass every
// assertion above forever.
func TestCoverageCheckFailsWhenAFixtureIsRemoved(t *testing.T) {
	root := filepath.Join("..", "testdata")

	phantom := append([]bench.Branch{}, bench.RefutationBranches...)
	phantom = append(phantom, bench.Branch{
		ID: "branch-with-no-fixture", Corpus: "refutation-suite",
		Wrong:  "stands in for the branch whose last sample was deleted",
		Family: "TAINT", Matcher: "none", Proposition: "nothing",
	})

	report, err := bench.CheckCoverage(root, phantom)
	if err != nil {
		t.Fatalf("CheckCoverage: %v", err)
	}
	if report.OK() {
		t.Fatal("coverage reported OK for a branch with no fixture; the check cannot fail and guards nothing")
	}
	var named bool
	for _, b := range report.Uncovered {
		if b.ID == "branch-with-no-fixture" {
			named = true
		}
	}
	if !named {
		t.Errorf("uncovered branch was not named in the report: %+v", report.Uncovered)
	}

	// And the empty registry must be an error, not a pass.
	if _, err := bench.CheckCoverage(root, nil); err == nil {
		t.Error("CheckCoverage over an empty registry returned no error; a vacuous pass is the failure mode")
	}
}
