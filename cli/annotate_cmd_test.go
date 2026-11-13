package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/annotate"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

func TestRunAnnotate_NoInput(t *testing.T) {
	// Should fail when no findings file exists.
	code := runAnnotate([]string{})
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing findings file, got %d", code)
	}
}

func TestRunAnnotate_MissingPRNumber(t *testing.T) {
	dir := t.TempDir()

	// Create a findings file.
	findingsPath := filepath.Join(dir, "findings.json")
	findingsContent := `{"version":"1.0","findings":[],"timestamp":"2025-01-01T00:00:00Z"}`
	if err := os.WriteFile(findingsPath, []byte(findingsContent), 0o644); err != nil {
		t.Fatalf("writing findings file: %v", err)
	}

	// Clear env vars that auto-detect PR number (may be set in CI).
	t.Setenv("GITHUB_REF", "")

	// Should fail when PR number can't be determined.
	code := runAnnotate([]string{"--input", findingsPath})
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing PR number, got %d", code)
	}
}

func TestRunAnnotate_MissingRepo(t *testing.T) {
	dir := t.TempDir()

	// Create a findings file.
	findingsPath := filepath.Join(dir, "findings.json")
	findingsContent := `{"version":"1.0","findings":[],"timestamp":"2025-01-01T00:00:00Z"}`
	if err := os.WriteFile(findingsPath, []byte(findingsContent), 0o644); err != nil {
		t.Fatalf("writing findings file: %v", err)
	}

	// Set PR number but explicitly clear repo (may be set in CI environment).
	t.Setenv("GITHUB_REF", "refs/pull/123/merge")
	t.Setenv("GITHUB_REPOSITORY", "")

	code := runAnnotate([]string{"--input", findingsPath})
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing repo, got %d", code)
	}
}

func TestRunAnnotate_NoFindings(t *testing.T) {
	dir := t.TempDir()

	// Create empty findings file.
	findingsPath := filepath.Join(dir, "findings.json")
	findingsContent := `{"version":"1.0","findings":[],"timestamp":"2025-01-01T00:00:00Z"}`
	if err := os.WriteFile(findingsPath, []byte(findingsContent), 0o644); err != nil {
		t.Fatalf("writing findings file: %v", err)
	}

	// Set required env vars.
	t.Setenv("GITHUB_REF", "refs/pull/123/merge")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")

	code := runAnnotate([]string{"--input", findingsPath})
	if code != 0 {
		t.Fatalf("expected exit code 0 for no findings, got %d", code)
	}
}

func TestRunAnnotate_InvalidJSON(t *testing.T) {
	dir := t.TempDir()

	// Create invalid findings file.
	findingsPath := filepath.Join(dir, "findings.json")
	findingsContent := `invalid json{`
	if err := os.WriteFile(findingsPath, []byte(findingsContent), 0o644); err != nil {
		t.Fatalf("writing findings file: %v", err)
	}

	// Set required env vars.
	t.Setenv("GITHUB_REF", "refs/pull/123/merge")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")

	code := runAnnotate([]string{"--input", findingsPath})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid JSON, got %d", code)
	}
}

func TestRunAnnotate_ViaRunCommand(t *testing.T) {
	// Test that the annotate command is recognized.
	code := run([]string{"annotate"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for annotate without findings, got %d", code)
	}
}

func TestRunAnnotate_InvalidFlag(t *testing.T) {
	code := runAnnotate([]string{"--invalid-flag"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid flag, got %d", code)
	}
}

func TestRunAnnotate_PRNumberFromFlag(t *testing.T) {
	dir := t.TempDir()

	// Create empty findings file.
	findingsPath := filepath.Join(dir, "findings.json")
	findingsContent := `{"version":"1.0","findings":[],"timestamp":"2025-01-01T00:00:00Z"}`
	if err := os.WriteFile(findingsPath, []byte(findingsContent), 0o644); err != nil {
		t.Fatalf("writing findings file: %v", err)
	}

	// Use --pr and --repo flags.
	code := runAnnotate([]string{"--input", findingsPath, "--pr", "42", "--repo", "owner/repo"})
	if code != 0 {
		t.Fatalf("expected exit code 0 for no findings with PR flag, got %d", code)
	}
}

func TestRunAnnotate_PRFromGitHubRef(t *testing.T) {
	dir := t.TempDir()

	// Create empty findings file.
	findingsPath := filepath.Join(dir, "findings.json")
	findingsContent := `{"version":"1.0","findings":[],"timestamp":"2025-01-01T00:00:00Z"}`
	if err := os.WriteFile(findingsPath, []byte(findingsContent), 0o644); err != nil {
		t.Fatalf("writing findings file: %v", err)
	}

	// Simulate GitHub Actions environment.
	t.Setenv("GITHUB_REF", "refs/pull/42/merge")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")

	code := runAnnotate([]string{"--input", findingsPath})
	if code != 0 {
		t.Fatalf("expected exit code 0 for no findings, got %d", code)
	}
}

func TestRunAnnotate_NonPullRef(t *testing.T) {
	dir := t.TempDir()

	findingsPath := filepath.Join(dir, "findings.json")
	findingsContent := `{"version":"1.0","findings":[],"timestamp":"2025-01-01T00:00:00Z"}`
	if err := os.WriteFile(findingsPath, []byte(findingsContent), 0o644); err != nil {
		t.Fatalf("writing findings file: %v", err)
	}

	// Set a non-pull GITHUB_REF - PR number should not be detected.
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")

	code := runAnnotate([]string{"--input", findingsPath})
	if code != 2 {
		t.Fatalf("expected exit code 2 for non-pull ref, got %d", code)
	}
}

func TestSeverityBadge_AllLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		severity findings.Severity
		expected string
	}{
		{findings.SeverityCritical, ":red_circle:"},
		{findings.SeverityHigh, ":orange_circle:"},
		{findings.SeverityMedium, ":yellow_circle:"},
		{findings.SeverityLow, ":large_blue_circle:"},
		{findings.SeverityInfo, ":white_circle:"},
		{"unknown", ":white_circle:"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			t.Parallel()
			result := annotate.SeverityBadge(tt.severity)
			if result != tt.expected {
				t.Errorf("SeverityBadge(%q) = %q, want %q", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestGetChangedFilesSet_NonGitRepo(t *testing.T) {
	dir := t.TempDir()

	// Change to non-git directory.
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	result := getChangedFilesSet()
	if result != nil {
		t.Fatal("expected nil for non-git directory")
	}
}

// fakeGH puts a gh on PATH that records each call's arguments and request
// body under dir, and answers as the real one does on success.
func fakeGH(t *testing.T) (logDir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake gh is a shell script")
	}
	bin, logDir := t.TempDir(), t.TempDir()
	script := "#!/bin/sh\nn=$(ls \"$GH_LOG\" | grep -c 'args$')\necho \"$@\" > \"$GH_LOG/$n.args\"\ncat > \"$GH_LOG/$n.body\"\necho '{}'\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GH_LOG", logDir)
	return logDir
}

func ghCall(t *testing.T, dir string, n int) (args string, body map[string]any) {
	t.Helper()
	a, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%d.args", n)))
	if err != nil {
		t.Fatalf("gh call %d was not made: %v", n, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%d.body", n)))
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("gh call %d body is not JSON: %v", n, err)
	}
	return strings.TrimSpace(string(a)), body
}

// The report nox itself writes (indented, one field per line) is read as
// findings, and the summary counts them by severity. #1016: the Action's
// sed parser counted "Total 2" over five zero severities and posted no inline
// comment, for exactly this report.
func TestRunAnnotate_SummaryFromTheReportNoxWrites(t *testing.T) {
	logDir := fakeGH(t)
	dir := t.TempDir()
	t.Chdir(dir) // not a git repository: no changed-files filter

	fs := findings.NewFindingSet()
	fs.Add(findings.NewFinding("IAC-306", findings.SeverityMedium, findings.ConfidenceHigh,
		findings.Location{FilePath: ".github/workflows/nox.yml", StartLine: 11}, "unpinned action"))
	fs.Add(findings.NewFinding("IAC-309", findings.SeverityLow, findings.ConfidenceHigh,
		findings.Location{FilePath: ".github/workflows/ci.yml", StartLine: 14}, "broad permissions"))
	path := filepath.Join(dir, "findings.json")
	if err := report.NewJSONReporter("test").WriteToFile(fs, path); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "\n      \"Severity\"") && !strings.Contains(string(raw), "\n    \"Severity\"") {
		t.Fatalf("the report is no longer indented; this test no longer reproduces #1016:\n%s", raw)
	}
	t.Setenv("GITHUB_REF", "refs/pull/1/merge")
	t.Setenv("GITHUB_REPOSITORY", "felixgeelhaar/ghostline")

	if code := runAnnotate([]string{"--input", path, "--summary", "--max-comments", "25", "--min-severity", "low"}); code != 0 {
		t.Fatalf("exit %d", code)
	}

	args, review := ghCall(t, logDir, 0)
	if args != "api repos/felixgeelhaar/ghostline/pulls/1/reviews --method POST --input -" {
		t.Errorf("review call: %s", args)
	}
	comments, _ := review["comments"].([]any)
	if len(comments) != 2 {
		t.Fatalf("review has %d inline comments, want 2: %v", len(comments), review)
	}
	first, _ := comments[0].(map[string]any)
	if first["path"] != ".github/workflows/nox.yml" || first["line"] != float64(11) {
		t.Errorf("first comment %v", first)
	}

	args, summary := ghCall(t, logDir, 1)
	if args != "api repos/felixgeelhaar/ghostline/issues/1/comments --method POST --input -" {
		t.Errorf("summary call: %s", args)
	}
	text, _ := summary["body"].(string)
	for _, want := range []string{"Medium | 1 |", "Low | 1 |", "Critical | 0 |", "**Total** | **2**", "2 inline comment(s) posted (max: 25, min severity: low)"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary lacks %q:\n%s", want, text)
		}
	}
}

// Without --summary nothing but the review is posted, and the bounds apply.
func TestRunAnnotate_BoundsWithoutSummary(t *testing.T) {
	logDir := fakeGH(t)
	dir := t.TempDir()
	t.Chdir(dir)
	fs := findings.NewFindingSet()
	fs.Add(findings.NewFinding("A", findings.SeverityLow, findings.ConfidenceHigh, findings.Location{FilePath: "a", StartLine: 1}, "a"))
	fs.Add(findings.NewFinding("B", findings.SeverityHigh, findings.ConfidenceHigh, findings.Location{FilePath: "b", StartLine: 2}, "b"))
	path := filepath.Join(dir, "findings.json")
	if err := report.NewJSONReporter("test").WriteToFile(fs, path); err != nil {
		t.Fatal(err)
	}
	if code := runAnnotate([]string{"--input", path, "--pr", "7", "--repo", "o/r", "--min-severity", "medium"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	_, review := ghCall(t, logDir, 0)
	if comments, _ := review["comments"].([]any); len(comments) != 1 {
		t.Errorf("review has %d comments, want only the high one", len(comments))
	}
	if _, err := os.Stat(filepath.Join(logDir, "1.args")); err == nil {
		t.Error("a summary was posted without --summary")
	}
}

func TestRunAnnotate_RejectsAnUnknownSeverity(t *testing.T) {
	if code := runAnnotate([]string{"--pr", "1", "--repo", "o/r", "--min-severity", "severe"}); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
}

func TestGetChangedFilesSet_InGitRepo(t *testing.T) {
	dir := t.TempDir()

	// Initialize a git repo.
	cmd := exec.Command("git", "init", "-b", "main")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir,
		// See core/diff: git may fork `gc --auto`, racing t.TempDir cleanup.
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=gc.auto", "GIT_CONFIG_VALUE_0=0",
		"GIT_CONFIG_KEY_1=maintenance.auto", "GIT_CONFIG_VALUE_1=false")
	if err := cmd.Run(); err != nil {
		t.Skipf("git not available: %v", err)
	}

	// Configure git user.
	for _, args := range [][]string{
		{"config", "user.email", "test@test.com"},
		{"config", "user.name", "Test"},
	} {
		cmd = exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
		_ = cmd.Run()
	}

	// Create initial commit.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# test"), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	_ = cmd.Run()
	cmd = exec.Command("git", "commit", "-m", "initial")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	_ = cmd.Run()

	// Change to git repo directory.
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	// getChangedFilesSet may return nil if origin/main doesn't exist,
	// which is fine since this is a local repo with no remote.
	result := getChangedFilesSet()
	// In a repo without a remote, this returns nil.
	_ = result
}
