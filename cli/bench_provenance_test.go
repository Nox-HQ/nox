package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// A fire-rate report must say which engine produced it and what it scanned.
//
// The 2026-Q2 report recorded neither. Its projects were temp paths that no
// longer existed, and nothing named the build. Four months later those counts
// were read as current and used to argue for work that had already shipped:
// the character-bounded proximity fix (eb46c32), which cut SEC findings on the
// same repositories by 89-99.9%. The numbers were not wrong when written. They
// became wrong by being unattributable, and nothing in the file said so.
//
// These tests are the part the file's shape was missing.

// TestBenchReportRecordsItsEngine. Without this the report cannot be compared
// against any other run, which is the only thing a benchmark is for.
func TestBenchReportRecordsItsEngine(t *testing.T) {
	b, err := json.Marshal(BenchReport{NoxVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	v, ok := got["nox_version"]
	if !ok {
		t.Fatal("a bench report serialises without `nox_version`; its counts cannot " +
			"be attributed to a build, and a stale report reads exactly like a current one")
	}
	if v == "" {
		t.Error("`nox_version` is empty")
	}
}

// TestProjectSummaryCarriesRepoIdentity. `path` is a temp directory; it
// identifies nothing once the run ends.
func TestProjectSummaryCarriesRepoIdentity(t *testing.T) {
	b, err := json.Marshal(ProjectSummary{
		Path: "/tmp/nox-bench-123/vercel--ai", Repo: "vercel/ai",
		Ref: "@ai-sdk/zai@3.0.10", Commit: "6c6c221",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"repo", "ref", "commit"} {
		if !strings.Contains(string(b), `"`+field+`":`) {
			t.Errorf("a project summary serialises without %q, so the report cannot say "+
				"what it measured", field)
		}
	}
}

// TestGitHeadSHAResolvesARealCheckout pins the helper against this repository,
// and must return "" rather than fail for a directory that is not a checkout —
// a hand-assembled --corpus is allowed to contain those.
func TestGitHeadSHAResolvesARealCheckout(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	got := gitHeadSHA("..")
	if len(got) != 40 {
		t.Errorf("gitHeadSHA on this repository = %q, want a 40-character commit", got)
	}
	if sha := gitHeadSHA(t.TempDir()); sha != "" {
		t.Errorf("gitHeadSHA on a non-checkout = %q, want \"\"; a corpus directory "+
			"need not be a git repository", sha)
	}
}
