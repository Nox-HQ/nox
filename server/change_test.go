package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runTestGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("git %v unavailable: %v: %s", args, err, out)
	}
}

const changeTestOldKey = "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" // nox:ignore SEC-001 -- test fixture

const changeTestNewKey = "AWS_KEY=AKIAV4NHT8QWE6YCBU2S\n" // nox:ignore SEC-001 -- test fixture

// The scan tool carries the change summary as structured content, from the
// same core code as the CLI: a second scan of the same path says what the edit
// in between introduced, and not what was already there.
func TestScanTool_StructuredChangeSinceTheLastScan(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "old.env"), []byte(changeTestOldKey), 0o644); err != nil {
		t.Fatal(err)
	}
	s := New("test", nil)

	first, err := s.handleScanStructured(context.Background(), scanInput{Path: dir})
	if err != nil || first.IsError {
		t.Fatalf("first scan: %v %+v", err, first)
	}
	if _, has := first.StructuredContent["change"]; has {
		t.Fatalf("the first scan has nothing to compare with; structured content = %v", first.StructuredContent)
	}

	if err := os.WriteFile(filepath.Join(dir, "new.env"), []byte(changeTestNewKey), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := s.handleScanStructured(context.Background(), scanInput{Path: dir})
	if err != nil || second.IsError {
		t.Fatalf("second scan: %v %+v", err, second)
	}
	ch, ok := second.StructuredContent["change"].(map[string]any)
	if !ok {
		t.Fatalf("no structured change on the second scan: %v", second.StructuredContent)
	}
	news, _ := ch["new"].([]any)
	if len(news) == 0 {
		t.Fatalf("change.new is empty: %v", ch)
	}
	for _, n := range news {
		if f, _ := n.(map[string]any)["file"].(string); f != "new.env" {
			t.Errorf("change.new lists %q, want only new.env", f)
		}
	}
}

// An explicit previous findings.json wins over the session, and must sit under
// an allowed path like any other path the tool reads.
func TestScanTool_PreviousFileAndAllowlist(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "old.env"), []byte(changeTestOldKey), 0o644); err != nil {
		t.Fatal(err)
	}
	s := New("test", []string{dir})
	if _, err := s.handleScan(context.Background(), scanInput{Path: dir}); err != nil {
		t.Fatal(err)
	}
	pc := s.getCache("")
	prev := filepath.Join(dir, "prev.json")
	if err := pc.result.JSONReporter("test").WriteToFile(pc.result.Findings, prev); err != nil {
		t.Fatal(err)
	}

	msg, delta := s.scanProject(scanInput{Path: dir, Previous: prev})
	if delta == nil || !delta.Empty() {
		t.Fatalf("scan against its own findings.json: %q, delta=%+v", msg, delta)
	}
	if !strings.Contains(delta.Since, "previous run") {
		t.Errorf("since = %q", delta.Since)
	}

	outside := filepath.Join(t.TempDir(), "prev.json")
	if msg, _ := s.scanProject(scanInput{Path: dir, Previous: outside}); !strings.HasPrefix(msg, "Error: ") {
		t.Errorf("a previous file outside the allowlist was read: %q", msg)
	}
}

// A previous findings.json written with --offline did not look advisories up.
// The scan tool must say so rather than list every advisory as new.
func TestScanTool_OfflinePreviousIsNotComparedOnAdvisories(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "old.env"), []byte(changeTestOldKey), 0o644); err != nil {
		t.Fatal(err)
	}
	s := New("test", []string{dir})
	if _, err := s.handleScan(context.Background(), scanInput{Path: dir}); err != nil {
		t.Fatal(err)
	}
	pc := s.getCache("")
	prev := filepath.Join(dir, "prev.json")
	rep := pc.result.JSONReporter("test")
	rep.Offline = true
	if err := rep.WriteToFile(pc.result.Findings, prev); err != nil {
		t.Fatal(err)
	}
	_, delta := s.scanProject(scanInput{Path: dir, Previous: prev})
	if delta == nil {
		t.Fatal("no delta")
	}
	found := false
	for _, c := range delta.Caveats {
		found = found || strings.Contains(c, "did not look up advisories")
	}
	if !found {
		t.Errorf("caveats = %v, want the advisory-lookup caveat", delta.Caveats)
	}
}

// The diff tool returns the shared delta.
func TestDiffTool_ReturnsTheDelta(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-b", "main"}, {"add", "."}, {"commit", "-m", "base"}} {
		runTestGit(t, dir, args...)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.env"), []byte(changeTestNewKey), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "."}, {"commit", "-m", "head"}} {
		runTestGit(t, dir, args...)
	}
	s := New("test", nil)
	res, err := s.handleDiff(context.Background(), diffInput{Path: dir, Base: "HEAD~1", Head: "HEAD", Offline: true})
	if err != nil || res.IsError {
		t.Fatalf("diff: %v %+v", err, res)
	}
	ch, ok := res.StructuredContent["change"].(map[string]any)
	if !ok {
		t.Fatalf("no change in the diff result: %v", res.StructuredContent)
	}
	if news, _ := ch["new"].([]any); len(news) == 0 {
		t.Errorf("change.new is empty: %v", ch)
	}
}
