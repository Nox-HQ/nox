package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/report"
)

// The whole chain, through a real scan and the artifact it writes.
//
// Every piece below is individually unit-tested, and that is exactly why this
// test exists: the pieces have been right before while the pipeline that joins
// them dropped the result on the floor. The reach-undetermined defect fixed in
// this same change was of that shape — a correct mapping function, a correct
// state vocabulary, and an analyzer whose `ok` guard meant neither was ever
// reached.
func TestCompetenceReachesTheArtifact(t *testing.T) {
	res, err := RunScan(filepath.Join("..", "testdata", "precision-suite"))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.CompetenceProfiles) < 2 {
		t.Fatalf("the scan holds %d competence profile(s); a corpus spanning Go, Python and "+
			"YAML cannot honestly have one", len(res.CompetenceProfiles))
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	if err := res.JSONReporter("test").WriteToFile(res.Findings, path); err != nil {
		t.Fatalf("writing report: %v", err)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // test-owned temp file
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	var rep report.JSONReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(rep.Meta.CompetenceProfiles) != len(res.CompetenceProfiles) {
		t.Fatalf("artifact carries %d profiles, scan held %d",
			len(rep.Meta.CompetenceProfiles), len(res.CompetenceProfiles))
	}

	// Every finding names a profile, and every named profile exists. A dangling
	// reference is worse than none: it reads as "competence was recorded" while
	// resolving to nothing.
	known := map[string]capability.Profile{}
	for _, p := range rep.Meta.CompetenceProfiles {
		known[p.ID] = p
	}
	seen := map[string]int{}
	for _, f := range rep.Findings {
		if f.CompetenceProfile == "" {
			t.Fatalf("%s at %s carries no competence profile", f.RuleID, f.Location.FilePath)
		}
		if _, ok := known[f.CompetenceProfile]; !ok {
			t.Fatalf("%s references profile %q, which the artifact does not define",
				f.RuleID, f.CompetenceProfile)
		}
		seen[f.CompetenceProfile]++
	}
	if len(seen) < 2 {
		t.Fatalf("every finding resolved to the same profile (%v); the artifact cannot "+
			"distinguish a finding nox lexed from one it could not read", seen)
	}

	// The subject counts on the profiles must match what the findings claim.
	// A profile that says it covers twenty findings while three reference it is
	// a summary nobody can trust.
	for id, n := range seen {
		if got := known[id].Subjects; got != n {
			t.Errorf("profile %s reports %d subjects, %d findings reference it", id, got, n)
		}
	}

	// A file with no lexer must not be reported as lexically analysed. This is
	// the concrete claim the run-level matrix cannot make: lexical_context is
	// provided and answered 48 subjects, and that says nothing about the ones
	// it could not read.
	var yamlProfile string
	for _, f := range rep.Findings {
		if filepath.Ext(f.Location.FilePath) == ".yaml" {
			yamlProfile = f.CompetenceProfile
			break
		}
	}
	if yamlProfile == "" {
		t.Skip("no YAML finding in the corpus to check")
	}
	var lexical bool
	for _, g := range known[yamlProfile].Gaps {
		if g.Capability == capability.LexicalContext && g.State == capability.Unsupported {
			lexical = true
		}
	}
	if !lexical {
		t.Error("a YAML finding's profile does not record lexical_context as unsupported; " +
			"the artifact claims nox distinguished code from comments in a file it has no " +
			"lexer for")
	}
}

// Determinism, at the artifact level. Profile IDs are part of the output now,
// and an artifact that renumbers between identical runs breaks CI caching,
// baseline diffs and the reproducibility claim.
func TestCompetenceProfilesAreStableAcrossRuns(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	render := func() string {
		res, err := RunScan(filepath.Join("..", "testdata", "precision-suite"))
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		data, err := res.JSONReporter("test").Generate(res.Findings)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		return string(data)
	}
	if a, b := render(), render(); a != b {
		t.Error("two identical scans produced different artifacts; competence profile " +
			"numbering is not deterministic")
	}
}
