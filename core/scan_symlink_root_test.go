package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/capability"
	reportpkg "github.com/nox-hq/nox/core/report"
)

// A scan target that is a symbolic link used to report NOTHING. Discovery
// walks with filepath.Walk, which Lstats its root: a link to a directory reads
// as a non-directory and is never descended, so the scan found zero artifacts,
// produced zero findings, and exited clean.
//
// It was found through `nox bench`, which has followed linked project
// directories since #723 -- a corpus of symlinked clones benched as all-clean.
// Measured on anthropic-sdk-python v0.40.0: 0 findings through a link, 16 by the
// real path. A clean result that comes from never having looked is the worst
// kind, because it reads exactly like a clean result.
//
// The contract: scanning through a link scans what it points at, with output
// identical to scanning the real path.

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func scanJSON(t *testing.T, target string) (report []byte, findings int) {
	t.Helper()
	res, err := RunScanWithOptions(target, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan %s: %v", target, err)
	}
	report, err = reportpkg.NewJSONReporter("test").Generate(res.Findings)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return report, len(res.Findings.Findings())
}

func TestScanThroughSymlinkedDirectoryMatchesRealPath(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	realDir := filepath.Join(t.TempDir(), "project")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixtureTree(t, realDir, map[string]string{
		"Dockerfile": "FROM ubuntu:latest\nRUN echo hi\n",
		"app.py":     "import os\nprompt = f\"Answer this: {user_input}\"\nmodel = \"gpt-4\"\n",
		"infra/main.tf": `resource "aws_s3_bucket" "b" {
  acl = "public-read"
}
`,
	})
	link := filepath.Join(t.TempDir(), "linked-project")
	symlinkOrSkip(t, realDir, link)

	want, n := scanJSON(t, realDir)
	if n == 0 {
		t.Fatal("fixture produced no findings; the comparison would be vacuous")
	}
	got, m := scanJSON(t, link)
	if m == 0 {
		t.Fatalf("scanning through a link found nothing; the real path finds %d", n)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("scan through a link differs from the real path (%d vs %d findings)\n--- real ---\n%s\n--- link ---\n%s",
			n, m, want, got)
	}
}

// A link several hops deep, and a relative link, resolve the same way.
func TestScanThroughChainedRelativeSymlink(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "project")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixtureTree(t, realDir, map[string]string{"Dockerfile": "FROM ubuntu:latest\n"})
	symlinkOrSkip(t, "project", filepath.Join(base, "hop1"))
	symlinkOrSkip(t, "hop1", filepath.Join(base, "hop2"))

	_, n := scanJSON(t, realDir)
	_, m := scanJSON(t, filepath.Join(base, "hop2"))
	if n == 0 || m != n {
		t.Errorf("real path: %d findings, through two relative links: %d", n, m)
	}
}

// A single-file target that is a link is scanned too.
func TestScanThroughSymlinkedFile(t *testing.T) {
	dir := t.TempDir()
	writeFixtureTree(t, dir, map[string]string{"Dockerfile": "FROM ubuntu:latest\nRUN echo hi\n"})
	link := filepath.Join(t.TempDir(), "Dockerfile")
	symlinkOrSkip(t, filepath.Join(dir, "Dockerfile"), link)

	_, n := scanJSON(t, filepath.Join(dir, "Dockerfile"))
	_, m := scanJSON(t, link)
	if n == 0 || m != n {
		t.Errorf("real file: %d findings, through a link: %d", n, m)
	}
}

// Discovery is not the only walk over the target: the Go call graph walks it
// too, and through an unresolved link it saw no functions, so every Go finding
// quietly lost its call-graph and entry-point answers. The findings themselves
// were identical, which is why only coverage shows it.
func TestCallGraphCoverageThroughSymlinkMatchesRealPath(t *testing.T) {
	realDir := mixedModule(t)
	link := filepath.Join(t.TempDir(), "linked-module")
	symlinkOrSkip(t, realDir, link)

	states := func(target string) map[string]string {
		res, err := RunScanWithOptions(target, ScanOptions{Offline: true})
		if err != nil {
			t.Fatalf("scan %s: %v", target, err)
		}
		out := map[string]string{}
		for _, f := range res.Findings.Findings() {
			if filepath.Ext(f.Location.FilePath) != ".go" {
				continue
			}
			for _, c := range []capability.AnalysisCapability{capability.CallGraph, capability.EntryPoint} {
				out[f.RuleID+"@"+f.Location.FilePath+":"+string(c)] = string(stateOf(t, res, f, c))
			}
		}
		return out
	}
	want, got := states(realDir), states(link)
	if len(want) == 0 {
		t.Fatal("the fixture produced no Go finding; this test asserts nothing")
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q by the real path, %q through a link", k, v, got[k])
		}
	}
}
