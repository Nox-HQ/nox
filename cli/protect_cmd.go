package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/git"
)

// hookMarker is written into the hook script so that uninstall can identify
// hooks managed by nox.
const hookMarker = "Installed by nox protect"

// runProtect implements the "nox protect" command with install, uninstall, and
// status subcommands for managing git pre-commit hooks.
func runProtect(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox protect <install|uninstall|status> [flags]")
		return 2
	}

	subcommand := args[0]
	remaining := args[1:]

	switch subcommand {
	case "install":
		return protectInstall(remaining)
	case "uninstall":
		return protectUninstall(remaining)
	case "status":
		return protectStatus(remaining)
	default:
		fmt.Fprintf(os.Stderr, "unknown protect subcommand: %s\n", subcommand)
		fmt.Fprintln(os.Stderr, "Usage: nox protect <install|uninstall|status> [flags]")
		return 2
	}
}

func protectInstall(args []string) int {
	fs := flag.NewFlagSet("protect install", flag.ContinueOnError)
	var (
		threshold string
		hookPath  string
		force     bool
	)
	fs.StringVar(&threshold, "severity-threshold", "high", "minimum severity to block commit (critical, high, medium, low)")
	fs.StringVar(&hookPath, "hook-path", "", "path to pre-commit hook file (default: auto-detect)")
	fs.BoolVar(&force, "force", false, "overwrite existing hook without prompting")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Validate severity threshold.
	if !isValidThreshold(threshold) {
		fmt.Fprintf(os.Stderr, "error: invalid severity threshold: %q (must be critical, high, medium, or low)\n", threshold)
		return 2
	}

	// Determine working directory.
	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}

	if !git.IsGitRepo(dir) {
		fmt.Fprintln(os.Stderr, "error: not a git repository")
		return 2
	}

	repoRoot, err := git.RepoRoot(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	// Resolve hook path.
	if hookPath == "" {
		hookPath = filepath.Join(repoRoot, ".git", "hooks", "pre-commit")
	}

	// Check for existing hook.
	if info, err := os.Stat(hookPath); err == nil && info.Size() > 0 {
		if !force {
			// Read existing hook to check if it was installed by nox.
			existing, readErr := os.ReadFile(hookPath)
			if readErr == nil && strings.Contains(string(existing), hookMarker) {
				fmt.Fprintln(os.Stderr, "error: nox pre-commit hook is already installed")
				fmt.Fprintln(os.Stderr, "  use --force to overwrite")
				return 2
			}
			fmt.Fprintln(os.Stderr, "error: pre-commit hook already exists at "+hookPath)
			fmt.Fprintln(os.Stderr, "  use --force to overwrite")
			return 2
		}
	}

	// Write the hook script.
	hookContent := generateHookScript(threshold)

	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: creating hooks directory: %v\n", err)
		return 2
	}

	if err := os.WriteFile(hookPath, []byte(hookContent), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing hook: %v\n", err)
		return 2
	}

	fmt.Printf("protect: installed pre-commit hook at %s\n", hookPath)
	fmt.Printf("protect: commits will be blocked on severity >= %s\n", threshold)
	return 0
}

func protectUninstall(args []string) int {
	fs := flag.NewFlagSet("protect uninstall", flag.ContinueOnError)
	var hookPath string
	fs.StringVar(&hookPath, "hook-path", "", "path to pre-commit hook file (default: auto-detect)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}

	if !git.IsGitRepo(dir) {
		fmt.Fprintln(os.Stderr, "error: not a git repository")
		return 2
	}

	repoRoot, err := git.RepoRoot(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	if hookPath == "" {
		hookPath = filepath.Join(repoRoot, ".git", "hooks", "pre-commit")
	}

	// Check if hook exists.
	content, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "error: no pre-commit hook found")
			return 2
		}
		fmt.Fprintf(os.Stderr, "error: reading hook: %v\n", err)
		return 2
	}

	// Verify it was installed by nox.
	if !strings.Contains(string(content), hookMarker) {
		fmt.Fprintln(os.Stderr, "error: pre-commit hook was not installed by nox — refusing to remove")
		return 2
	}

	if err := os.Remove(hookPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: removing hook: %v\n", err)
		return 2
	}

	fmt.Printf("protect: removed pre-commit hook from %s\n", hookPath)
	return 0
}

func protectStatus(args []string) int {
	fs := flag.NewFlagSet("protect status", flag.ContinueOnError)
	var hookPath string
	fs.StringVar(&hookPath, "hook-path", "", "path to pre-commit hook file (default: auto-detect)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}

	if !git.IsGitRepo(dir) {
		fmt.Fprintln(os.Stderr, "error: not a git repository")
		return 2
	}

	repoRoot, err := git.RepoRoot(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	if hookPath == "" {
		hookPath = filepath.Join(repoRoot, ".git", "hooks", "pre-commit")
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("protect: not installed")
			return 0
		}
		fmt.Fprintf(os.Stderr, "error: reading hook: %v\n", err)
		return 2
	}

	if strings.Contains(string(content), hookMarker) {
		fmt.Println("protect: installed")
	} else {
		fmt.Println("protect: not installed (pre-commit hook exists but was not installed by nox)")
	}
	return 0
}

// generateHookScript produces the shell script content for the pre-commit hook.
func generateHookScript(threshold string) string {
	return fmt.Sprintf(`#!/bin/sh
# %s - https://github.com/nox-hq/nox
# To uninstall: nox protect uninstall

nox scan --staged --severity-threshold %s --quiet .
exit_code=$?
if [ $exit_code -eq 1 ]; then
    echo ""
    echo "nox: commit blocked — secrets or security issues found in staged files" # nox:ignore SEC-163 -- em dash in string not hex
    echo "nox: use '// nox:ignore RULE-ID -- reason' to suppress false positives"
    echo "nox: use 'git commit --no-verify' to skip this check (not recommended)"
    exit 1
fi
exit 0
`, hookMarker, threshold)
}

// isValidThreshold returns true if the given string is a recognized severity
// threshold value.
func isValidThreshold(s string) bool {
	switch s {
	case "critical", "high", "medium", "low":
		return true
	}
	return false
}
