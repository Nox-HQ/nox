package deps

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reach"
)

// goModuleWithDep writes a real, buildable Go module requiring one dependency,
// and returns the artifact list the analyzer takes.
//
// Both halves matter. It must be a real module because the reachability path
// shells out to the toolchain — the first version of this helper wrote a go.mod
// and no source, so `go list -deps ./...` failed, every case came back
// undetermined for that reason, and a test written for the other branch would
// have passed for the wrong one.
//
// The source imports only the standard library, like the reachability suite's
// own fixtures, so the toolchain needs no network and no module cache. A
// fixture that needed either would be one that quietly stopped running, and the
// first thing anyone would notice is that it had stopped failing.
func goModuleWithDep(t *testing.T, module, version string) []discovery.Artifact {
	t.Helper()
	dir := t.TempDir()
	body := "module example.com/app\n\ngo 1.21\n\nrequire " + module + " " + version + "\n"
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	src := "package main\n\nimport (\n\t\"crypto/sha256\"\n\t\"fmt\"\n)\n\n" +
		"func main() { fmt.Printf(\"%x\\n\", sha256.Sum256([]byte(\"x\"))) }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing main.go: %v", err)
	}
	return []discovery.Artifact{{Path: "go.mod", AbsPath: path, Type: discovery.Lockfile}}
}

// The end of the chain, asserted through the real analyzer rather than through
// the helper it calls.
//
// applyReachMetadata being correct proves nothing on its own — the defect was
// never in the writing, it was that the ANALYZER only called it for outcomes
// that concluded something. goSymbolReferenced returns ok=false for every
// undetermined result, that value gated the whole block, and so an advisory
// with no ecosystem_specific.imports produced a finding carrying no reach
// annotation at all.
//
// That is the common case, not an edge one: only the Go vulndb populates import
// metadata, so every GHSA-sourced Go advisory lands here. Downstream, the
// capability matrix read those findings as never-evaluated, and the Undetermined
// arm of the switch that maps them was unreachable code.
func TestAnalyzerRecordsUndeterminedReachability(t *testing.T) {
	src := &stubSource{
		name: "stub",
		records: map[string][]vulnsource.Record{
			"golang.org/x/text": {{
				ID:      "STUB-NO-IMPORTS",
				Summary: "advisory with no import metadata",
				// Affected names the module and NOTHING under
				// ecosystem_specific.imports — the shape that scopes an
				// advisory to a whole module.
				Affected: []vulnsource.Affected{{
					Package: vulnsource.Package{Name: "golang.org/x/text", Ecosystem: "Go"},
				}},
			}},
		},
	}

	artifacts := goModuleWithDep(t, "golang.org/x/text", "v0.3.7")
	_, fs, err := NewAnalyzer(WithSource(src)).ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}

	f := vulnFinding(t, fs)
	if got := f.Metadata["reach_outcome"]; got != string(reach.Undetermined) {
		t.Errorf("reach_outcome = %q, want %q. A finding whose reachability was asked and "+
			"could not be answered must not arrive looking like one nobody asked about.",
			got, reach.Undetermined)
	}
	if f.Metadata["reach_level"] != string(reach.SymbolReferenced) {
		t.Errorf("reach_level = %q, want %q", f.Metadata["reach_level"], reach.SymbolReferenced)
	}
	if f.Metadata["reach_limitations"] == "" {
		t.Error("reach_limitations is empty; an operator cannot act on an undetermined answer " +
			"that does not say what defeated it")
	}
	// The severity must NOT drop. Only a refutation earns that, and an
	// undetermined result is not a refutation however much it resembles one in
	// the output.
	if f.Severity == findings.SeverityInfo {
		t.Error("an undetermined reachability result demoted the finding to info; only a " +
			"deterministic refutation may do that")
	}
}

// An advisory that DOES name its affected imports still reaches a CONCLUSION.
// The unconditional write must not have turned the deciding paths into
// undetermined ones.
//
// This module requires x/text and imports only the standard library, so the
// toolchain enumerates the whole closure and the affected import is genuinely
// not in it: refuted, and severity may drop. That is the one basis on which a
// finding is allowed to be demoted, and the test asserts the demotion happens
// here so the previous test's assertion that it does NOT happen on an
// undetermined result means something.
func TestAnalyzerStillConcludesReachability(t *testing.T) {
	src := &stubSource{
		name: "stub",
		records: map[string][]vulnsource.Record{
			"golang.org/x/text": {{
				ID:      "STUB-WITH-IMPORTS",
				Summary: "advisory naming an affected import",
				Affected: []vulnsource.Affected{{
					Package: vulnsource.Package{Name: "golang.org/x/text", Ecosystem: "Go"},
					EcosystemSpecific: vulnsource.EcosystemSpecific{
						Imports: []vulnsource.Import{{Path: "golang.org/x/text/language"}},
					},
				}},
			}},
		},
	}

	artifacts := goModuleWithDep(t, "golang.org/x/text", "v0.3.7")
	_, fs, err := NewAnalyzer(WithSource(src)).ScanArtifacts(context.Background(), artifacts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}

	f := vulnFinding(t, fs)
	if got := f.Metadata["reach_outcome"]; got == "" {
		t.Fatal("reach_outcome is absent on an advisory that named its affected imports")
	}
	if f.Metadata["affected_imports"] == "" {
		t.Error("affected_imports is absent; the advisory named one")
	}
	if got := f.Metadata["reach_outcome"]; got != string(reach.Refuted) {
		t.Errorf("reach_outcome = %q, want %q: the toolchain enumerated the whole closure "+
			"and the affected import is not in it", got, reach.Refuted)
	}
	if f.Metadata["reach_limitations"] != "" {
		t.Errorf("a refuted result carries limitations %q; reach.Refute must refuse to build "+
			"a negative from an incomplete scope at all", f.Metadata["reach_limitations"])
	}
	if f.Severity != findings.SeverityInfo {
		t.Errorf("severity = %q on a refuted result, want info", f.Severity)
	}
}
