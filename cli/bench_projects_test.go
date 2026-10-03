package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/internal/testlink"
)

// A hand-assembled corpus is often links to clones that already exist. bench
// skipped every entry that was not a plain directory, so a corpus of seven
// symlinked repositories produced "0 projects" — and a report, and exit 0.
func TestBenchProjects_FollowsLinkedDirectories(t *testing.T) {
	corpus := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.Mkdir(filepath.Join(corpus, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(elsewhere, "clone"), 0o755); err != nil {
		t.Fatal(err)
	}
	testlink.Symlink(t, filepath.Join(elsewhere, "clone"), filepath.Join(corpus, "linked"))
	if err := os.WriteFile(filepath.Join(corpus, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(corpus, "notes.txt"), filepath.Join(corpus, "link-to-file")); err != nil {
		t.Fatal(err)
	}

	got, err := benchProjects(corpus)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "linked,real" {
		t.Errorf("projects = %v, want linked and real", got)
	}
}

// A benchmark of nothing is not a benchmark. An empty corpus used to write a
// report with no projects and exit 0, which reads exactly like a clean run.
func TestBench_ACorpusWithNoProjectsFails(t *testing.T) {
	corpus := t.TempDir()
	if err := os.WriteFile(filepath.Join(corpus, "README"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bench.json")
	if code := runBench([]string{"--corpus", corpus, "--output", out, "--quiet"}); code == 0 {
		t.Fatal("a corpus with no projects must not succeed")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("no report should be written for a corpus with no projects")
	}
}
