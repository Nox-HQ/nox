package deps

import (
	"context"
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/discovery"
)

// A monorepo pins the same package in many lockfiles. Each lockfile still gets
// its own finding, but the source is asked about the package once: llama_index
// has ~600 lockfiles, and one query per lockfile entry ran past the lookup's
// time budget, so the batches after it were never sent and every advisory in
// them went unreported.
func TestLookupAsksOncePerPackageAndReportsEveryLockfile(t *testing.T) {
	src := &stubSource{
		name: "stub",
		records: map[string][]vulnsource.Record{
			"lodash": {{ID: "STUB-0001", Summary: "Prototype pollution"}},
		},
	}

	var artifacts []discovery.Artifact
	for range 3 {
		_, a := npmLockfile(t, "lodash", "4.17.20")
		artifacts = append(artifacts, a...)
	}
	_, other := npmLockfile(t, "lodash", "4.17.21")
	artifacts = append(artifacts, other...)

	a := NewAnalyzer(WithSource(src), WithOSVBaseURL("http://127.0.0.1:1"))
	_, fs, err := a.ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}

	if len(src.queries) != 2 {
		t.Fatalf("source asked %d queries, want 2 (one per distinct package version): %+v",
			len(src.queries), src.queries)
	}

	perFile := map[string]int{}
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-001" {
			perFile[f.Location.FilePath]++
		}
	}
	if len(perFile) != 4 {
		t.Fatalf("VULN-001 reported in %d lockfiles, want all 4: %v", len(perFile), perFile)
	}
	for file, n := range perFile {
		if n != 1 {
			t.Errorf("%s: %d VULN-001 findings, want 1", file, n)
		}
	}
}
