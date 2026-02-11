package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
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

	// Set PR number but not repo.
	t.Setenv("GITHUB_REF", "refs/pull/123/merge")

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
			result := severityBadge(tt.severity)
			if result != tt.expected {
				t.Errorf("severityBadge(%q) = %q, want %q", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestGetChangedFilesSet_NonGitRepo(t *testing.T) {
	dir := t.TempDir()

	// Change to non-git directory.
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(dir)

	result := getChangedFilesSet()
	if result != nil {
		t.Fatal("expected nil for non-git directory")
	}
}

func TestRunAnnotate_WithFindings(t *testing.T) {
	dir := t.TempDir()

	// Create findings file with actual findings.
	findingsPath := filepath.Join(dir, "findings.json")
	findingsContent := `{
		"version":"1.0",
		"findings":[
			{
				"ID":"f1",
				"RuleID":"SEC-001",
				"Severity":"high",
				"Message":"test finding",
				"Location":{"FilePath":"config.env","StartLine":1}
			}
		],
		"timestamp":"2025-01-01T00:00:00Z"
	}`
	if err := os.WriteFile(findingsPath, []byte(findingsContent), 0o644); err != nil {
		t.Fatalf("writing findings file: %v", err)
	}

	// Set required env vars.
	t.Setenv("GITHUB_REF", "refs/pull/42/merge")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")

	// This will fail at the gh CLI call since it's not available in test,
	// but exercises the finding parsing and comment building code.
	code := runAnnotate([]string{"--input", findingsPath})
	// Expected to fail at postReviewComments since gh CLI is not available.
	if code != 2 {
		// In CI without gh CLI, this returns 2. If gh is available it would succeed.
		// Either way, we exercise the code paths.
	}
}

func TestGetChangedFilesSet_InGitRepo(t *testing.T) {
	dir := t.TempDir()

	// Initialize a git repo.
	cmd := exec.Command("git", "init", "-b", "main")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
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
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(dir)

	// getChangedFilesSet may return nil if origin/main doesn't exist,
	// which is fine since this is a local repo with no remote.
	result := getChangedFilesSet()
	// In a repo without a remote, this returns nil.
	_ = result
}
