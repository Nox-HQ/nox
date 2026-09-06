package bench

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCorpus(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestParseCoverageFindsClaims(t *testing.T) {
	root := writeCorpus(t, map[string]string{
		"suite/a.py": "# nox-cover: alpha\nx = 1\n",
		"suite/b.go": "// nox-cover: beta, gamma\npackage p\n",
	})

	claims, err := ParseCoverage(filepath.Join(root, "suite"))
	if err != nil {
		t.Fatalf("ParseCoverage: %v", err)
	}
	got := map[string]string{}
	for _, c := range claims {
		got[c.BranchID] = c.FilePath
	}
	for _, want := range []string{"alpha", "beta", "gamma"} {
		if _, ok := got[want]; !ok {
			t.Errorf("claim %q not parsed; got %v", want, got)
		}
	}
	if len(claims) != 3 {
		t.Errorf("got %d claims, want 3: %+v", len(claims), claims)
	}
}

// A README explaining the annotation format must not be able to satisfy the
// coverage it documents — the same rule ParseCorpus applies to expectations.
// Without this, every branch could be "covered" by prose describing it.
func TestParseCoverageIgnoresDocsAndArtifacts(t *testing.T) {
	root := writeCorpus(t, map[string]string{
		"suite/README.md":     "Annotate a sample with `nox-cover: alpha` to claim a branch.\n",
		"suite/baseline.json": `{"note": "nox-cover: beta"}`,
		"suite/real.py":       "# nox-cover: gamma\n",
	})

	claims, err := ParseCoverage(filepath.Join(root, "suite"))
	if err != nil {
		t.Fatalf("ParseCoverage: %v", err)
	}
	if len(claims) != 1 || claims[0].BranchID != "gamma" {
		t.Errorf("docs or harness artifacts satisfied coverage: %+v", claims)
	}
}

func TestCheckCoverageReportsUncovered(t *testing.T) {
	root := writeCorpus(t, map[string]string{"suite/a.py": "# nox-cover: alpha\n"})

	report, err := CheckCoverage(root, []Branch{
		{ID: "alpha", Corpus: "suite", Wrong: "w", Family: "F", Matcher: "m", Proposition: "p"},
		{ID: "orphan", Corpus: "suite", Wrong: "w", Family: "F", Matcher: "m", Proposition: "p"},
	})
	if err != nil {
		t.Fatalf("CheckCoverage: %v", err)
	}
	if report.OK() {
		t.Fatal("report OK with an uncovered branch")
	}
	if len(report.Uncovered) != 1 || report.Uncovered[0].ID != "orphan" {
		t.Errorf("uncovered = %+v, want just orphan", report.Uncovered)
	}
	if len(report.Covered["alpha"]) != 1 {
		t.Errorf("alpha should have one witness, got %+v", report.Covered["alpha"])
	}
}

// A claim naming a branch nobody registered guards nothing, and it is the
// shape a rename leaves behind: the branch moves, the fixture keeps the old
// slug, and coverage would otherwise report the new branch uncovered without
// saying that a fixture for it is sitting right there under the old name.
func TestCheckCoverageReportsUnknownClaims(t *testing.T) {
	root := writeCorpus(t, map[string]string{"suite/a.py": "# nox-cover: typo\n"})

	report, err := CheckCoverage(root, []Branch{
		{ID: "alpha", Corpus: "suite", Wrong: "w", Family: "F", Matcher: "m", Proposition: "p"},
	})
	if err != nil {
		t.Fatalf("CheckCoverage: %v", err)
	}
	if len(report.Unknown) != 1 || report.Unknown[0].BranchID != "typo" {
		t.Errorf("unknown = %+v, want the typo claim", report.Unknown)
	}
	if len(report.Uncovered) != 1 {
		t.Errorf("alpha should still be uncovered; got %+v", report.Uncovered)
	}
}

// A fixture filed under the wrong corpus is scored by the wrong guard: a case
// that belongs in refutation-hard, dropped into refutation-suite, is scored
// for precision, and a case that must produce no verdict becomes a false
// positive nobody can explain.
func TestCheckCoverageReportsMisfiledClaims(t *testing.T) {
	root := writeCorpus(t, map[string]string{
		"suite/a.py": "# nox-cover: alpha\n",
		"hard/b.go":  "// nox-cover: alpha\n",
	})

	report, err := CheckCoverage(root, []Branch{
		{ID: "alpha", Corpus: "suite", Wrong: "w", Family: "F", Matcher: "m", Proposition: "p"},
		{ID: "beta", Corpus: "hard", Wrong: "w", Family: "F", Matcher: "m", Proposition: "p"},
	})
	if err != nil {
		t.Fatalf("CheckCoverage: %v", err)
	}
	if len(report.Misfiled) != 1 || report.Misfiled[0].Corpus != "hard" {
		t.Errorf("misfiled = %+v, want the hard/ claim", report.Misfiled)
	}
}

// An empty registry is the vacuous pass this whole mechanism exists to
// prevent: coverage over no branches is complete by definition.
func TestCheckCoverageRejectsAnEmptyRegistry(t *testing.T) {
	root := writeCorpus(t, map[string]string{"suite/a.py": "# nox-cover: alpha\n"})
	if _, err := CheckCoverage(root, nil); err == nil {
		t.Error("empty registry accepted; a coverage check over nothing passes vacuously")
	}
}

func TestCheckCoverageRejectsDuplicateAndMalformedBranches(t *testing.T) {
	root := writeCorpus(t, map[string]string{"suite/a.py": "# nox-cover: alpha\n"})
	dup := []Branch{
		{ID: "alpha", Corpus: "suite", Wrong: "w", Family: "F", Matcher: "m", Proposition: "p"},
		{ID: "alpha", Corpus: "suite", Wrong: "w", Family: "F", Matcher: "m", Proposition: "p"},
	}
	if _, err := CheckCoverage(root, dup); err == nil {
		t.Error("duplicate branch IDs accepted; the second entry would be invisible")
	}
	if _, err := CheckCoverage(root, []Branch{{ID: "alpha"}}); err == nil {
		t.Error("branch with no corpus accepted; nothing would be read for it")
	}
}

// A corpus a branch names but that does not exist must be an error. Returning
// "no claims found" for a missing directory turns a moved corpus into a silent
// coverage failure with a misleading cause.
func TestCheckCoverageRejectsAMissingCorpus(t *testing.T) {
	root := writeCorpus(t, map[string]string{"suite/a.py": "# nox-cover: alpha\n"})
	_, err := CheckCoverage(root, []Branch{
		{ID: "alpha", Corpus: "not-there", Wrong: "w", Family: "F", Matcher: "m", Proposition: "p"},
	})
	if err == nil {
		t.Error("missing corpus directory accepted")
	}
}
