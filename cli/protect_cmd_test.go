package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// setupProtectRepo creates a temp directory with an initialized git repo.
func setupProtectRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitRun(t, dir, "init", "-b", "main")
	gitRun(t, dir, "config", "user.email", "test@test.com")
	gitRun(t, dir, "config", "user.name", "Test")

	writeTestFile(t, filepath.Join(dir, "README.md"), "# Test\n")
	gitRun(t, dir, "add", ".")
	gitRun(t, dir, "commit", "-m", "initial")
	return dir
}

// gitRun runs a git command in the given directory.
func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// writeTestFile writes a file with the given content.
func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating dir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func TestProtect_Install(t *testing.T) {
	dir := setupProtectRepo(t)
	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")

	code := run([]string{"protect", "install", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify hook exists.
	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("hook not found: %v", err)
	}

	// Verify hook is executable.
	if info.Mode()&0o111 == 0 {
		t.Fatal("hook is not executable")
	}

	// Verify hook contains marker.
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("reading hook: %v", err)
	}
	if !strings.Contains(string(content), hookMarker) {
		t.Fatal("hook does not contain nox marker")
	}

	// Verify hook contains the severity threshold.
	if !strings.Contains(string(content), "--severity-threshold high") {
		t.Fatal("hook does not contain default severity threshold")
	}
}

func TestProtect_InstallCustomThreshold(t *testing.T) {
	dir := setupProtectRepo(t)
	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")

	code := run([]string{"protect", "install", "--severity-threshold", "critical", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("reading hook: %v", err)
	}
	if !strings.Contains(string(content), "--severity-threshold critical") {
		t.Fatal("hook does not contain custom severity threshold")
	}
}

func TestProtect_Uninstall(t *testing.T) {
	dir := setupProtectRepo(t)
	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")

	// Install first.
	code := run([]string{"protect", "install", dir})
	if code != 0 {
		t.Fatalf("install failed with exit code %d", code)
	}

	// Uninstall.
	code = run([]string{"protect", "uninstall", dir})
	if code != 0 {
		t.Fatalf("uninstall failed with exit code %d", code)
	}

	// Verify hook is removed.
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Fatal("hook still exists after uninstall")
	}
}

func TestProtect_UninstallRefusesNonNoxHook(t *testing.T) {
	dir := setupProtectRepo(t)
	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")

	// Write a non-nox hook.
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		t.Fatalf("creating hooks dir: %v", err)
	}
	writeTestFile(t, hookPath, "#!/bin/sh\necho other hook\n")

	code := run([]string{"protect", "uninstall", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for non-nox hook, got %d", code)
	}

	// Verify hook was NOT removed.
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		t.Fatal("non-nox hook was removed when it should have been preserved")
	}
}

func TestProtect_Status_Installed(t *testing.T) {
	dir := setupProtectRepo(t)

	// Install first.
	code := run([]string{"protect", "install", dir})
	if code != 0 {
		t.Fatalf("install failed with exit code %d", code)
	}

	code = run([]string{"protect", "status", dir})
	if code != 0 {
		t.Fatalf("status failed with exit code %d", code)
	}
}

func TestProtect_Status_NotInstalled(t *testing.T) {
	dir := setupProtectRepo(t)

	code := run([]string{"protect", "status", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for not installed, got %d", code)
	}
}

func TestProtect_AlreadyInstalled(t *testing.T) {
	dir := setupProtectRepo(t)

	// Install first.
	code := run([]string{"protect", "install", dir})
	if code != 0 {
		t.Fatalf("first install failed with exit code %d", code)
	}

	// Try to install again without --force.
	code = run([]string{"protect", "install", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for duplicate install, got %d", code)
	}
}

func TestProtect_AlreadyInstalled_Force(t *testing.T) {
	dir := setupProtectRepo(t)

	// Install first.
	code := run([]string{"protect", "install", dir})
	if code != 0 {
		t.Fatalf("first install failed with exit code %d", code)
	}

	// Force reinstall.
	code = run([]string{"protect", "install", "--force", dir})
	if code != 0 {
		t.Fatalf("force reinstall failed with exit code %d", code)
	}
}

func TestProtect_NotGitRepo(t *testing.T) {
	dir := t.TempDir()

	code := run([]string{"protect", "install", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for non-git dir, got %d", code)
	}
}

func TestProtect_InvalidThreshold(t *testing.T) {
	dir := setupProtectRepo(t)

	code := run([]string{"protect", "install", "--severity-threshold", "invalid", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid threshold, got %d", code)
	}
}

func TestProtect_NoSubcommand(t *testing.T) {
	code := run([]string{"protect"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing subcommand, got %d", code)
	}
}

func TestProtect_UnknownSubcommand(t *testing.T) {
	code := run([]string{"protect", "foo"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for unknown subcommand, got %d", code)
	}
}

func TestProtect_UninstallNoHook(t *testing.T) {
	dir := setupProtectRepo(t)

	// Uninstall without any hook installed.
	code := run([]string{"protect", "uninstall", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for no hook, got %d", code)
	}
}

func TestProtect_Status_NonNoxHook(t *testing.T) {
	dir := setupProtectRepo(t)
	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")

	// Write a non-nox hook.
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		t.Fatalf("creating hooks dir: %v", err)
	}
	writeTestFile(t, hookPath, "#!/bin/sh\necho other hook\n")

	code := run([]string{"protect", "status", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 for non-nox hook status, got %d", code)
	}
}

func TestProtect_InstallCustomHookPath(t *testing.T) {
	dir := setupProtectRepo(t)
	hookPath := filepath.Join(dir, "custom-hooks", "pre-commit")

	code := protectInstall([]string{"--hook-path", hookPath, dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 with custom hook path, got %d", code)
	}

	// Verify hook was written.
	if _, err := os.Stat(hookPath); err != nil {
		t.Fatalf("hook not found at custom path: %v", err)
	}
}

func TestProtect_UninstallCustomHookPath(t *testing.T) {
	dir := setupProtectRepo(t)
	hookPath := filepath.Join(dir, "custom-hooks", "pre-commit")

	// Install first.
	code := protectInstall([]string{"--hook-path", hookPath, dir})
	if code != 0 {
		t.Fatalf("install failed: %d", code)
	}

	// Uninstall with custom path.
	code = protectUninstall([]string{"--hook-path", hookPath, dir})
	if code != 0 {
		t.Fatalf("uninstall failed: %d", code)
	}

	// Verify hook was removed.
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Fatal("hook still exists after uninstall")
	}
}

func TestProtect_StatusCustomHookPath(t *testing.T) {
	dir := setupProtectRepo(t)
	hookPath := filepath.Join(dir, "custom-hooks", "pre-commit")

	// Install first.
	code := protectInstall([]string{"--hook-path", hookPath, dir})
	if code != 0 {
		t.Fatalf("install failed: %d", code)
	}

	code = protectStatus([]string{"--hook-path", hookPath, dir})
	if code != 0 {
		t.Fatalf("status failed: %d", code)
	}
}

func TestProtect_InstallExistingNonNoxHookRequiresForce(t *testing.T) {
	dir := setupProtectRepo(t)
	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")

	// Write a non-nox hook.
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		t.Fatalf("creating hooks dir: %v", err)
	}
	writeTestFile(t, hookPath, "#!/bin/sh\necho other hook\n")

	// Install without --force should fail.
	code := run([]string{"protect", "install", dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for existing non-nox hook, got %d", code)
	}

	// Install with --force should succeed.
	code = run([]string{"protect", "install", "--force", dir})
	if code != 0 {
		t.Fatalf("expected exit code 0 with --force, got %d", code)
	}
}

func TestProtect_InstallNotGitRepo_Direct(t *testing.T) {
	dir := t.TempDir()

	code := protectInstall([]string{dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for non-git dir, got %d", code)
	}
}

func TestProtect_UninstallNotGitRepo(t *testing.T) {
	dir := t.TempDir()

	code := protectUninstall([]string{dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for non-git dir, got %d", code)
	}
}

func TestProtect_StatusNotGitRepo(t *testing.T) {
	dir := t.TempDir()

	code := protectStatus([]string{dir})
	if code != 2 {
		t.Fatalf("expected exit code 2 for non-git dir, got %d", code)
	}
}

func TestProtect_InstallInvalidFlag(t *testing.T) {
	code := protectInstall([]string{"--invalid-flag"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid flag, got %d", code)
	}
}

func TestProtect_UninstallInvalidFlag(t *testing.T) {
	code := protectUninstall([]string{"--invalid-flag"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid flag, got %d", code)
	}
}

func TestProtect_StatusInvalidFlag(t *testing.T) {
	code := protectStatus([]string{"--invalid-flag"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid flag, got %d", code)
	}
}

func TestProtect_InstallAllThresholds(t *testing.T) {
	for _, threshold := range []string{"critical", "high", "medium", "low"} {
		t.Run(threshold, func(t *testing.T) {
			dir := setupProtectRepo(t)
			hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")

			code := protectInstall([]string{"--severity-threshold", threshold, dir})
			if code != 0 {
				t.Fatalf("expected exit code 0 for %s threshold, got %d", threshold, code)
			}

			content, err := os.ReadFile(hookPath)
			if err != nil {
				t.Fatalf("reading hook: %v", err)
			}
			if !strings.Contains(string(content), "--severity-threshold "+threshold) {
				t.Fatalf("hook does not contain threshold %s", threshold)
			}
		})
	}
}

func TestGenerateHookScript(t *testing.T) {
	t.Parallel()

	script := generateHookScript("high")

	if !strings.Contains(script, hookMarker) {
		t.Error("hook script should contain the hook marker")
	}
	if !strings.Contains(script, "--severity-threshold high") {
		t.Error("hook script should contain severity threshold")
	}
	if !strings.HasPrefix(script, "#!/bin/sh") {
		t.Error("hook script should start with shebang")
	}
}

func TestIsValidThreshold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected bool
	}{
		{"critical", true},
		{"high", true},
		{"medium", true},
		{"low", true},
		{"info", false},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			if got := isValidThreshold(tt.input); got != tt.expected {
				t.Errorf("isValidThreshold(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
