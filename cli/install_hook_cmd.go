package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// runInstallHook installs a git hook that scans before a commit (the index)
// or a push (the working tree) and blocks on findings at or above a severity.
// --no-verify skips it, as it does any hook.
func runInstallHook(args []string) int {
	fs := flag.NewFlagSet("install-hook", flag.ContinueOnError)
	var (
		repoPath string
		hookKind string
		failOn   string
		bin      string
		force    bool
	)
	fs.StringVar(&repoPath, "repo", ".", "path to the git repository")
	fs.StringVar(&hookKind, "kind", "pre-commit", "hook kind: pre-commit or pre-push")
	fs.StringVar(&failOn, "fail-on", "critical,high", "severities that fail the hook, comma-separated; the hook blocks the least severe one listed and everything above it")
	fs.StringVar(&bin, "bin", "nox", "name or path of the nox binary the hook should call")
	fs.BoolVar(&force, "force", false, "overwrite existing hook script")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	switch hookKind {
	case "pre-commit", "pre-push":
	default:
		fmt.Fprintf(os.Stderr, "error: --kind must be pre-commit or pre-push, got %q\n", hookKind)
		return 2
	}

	threshold, err := thresholdFromFailOn(failOn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	hooksDir := filepath.Join(repoPath, ".git", "hooks")
	if info, err := os.Stat(hooksDir); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %s is not a git repository (no .git/hooks directory)\n", repoPath)
		return 2
	}

	hookPath := filepath.Join(hooksDir, hookKind)
	if !force {
		if _, err := os.Stat(hookPath); err == nil {
			fmt.Fprintf(os.Stderr, "error: %s already exists; pass --force to overwrite\n", hookPath)
			return 2
		}
	}

	script := hookSpec{
		kind:      hookKind,
		bin:       bin,
		threshold: threshold,
		header: []string{
			"Installed by `nox install-hook --kind " + hookKind + "`.",
			"Skip once with --no-verify.",
		},
		skipIfMissing: true,
	}.render()
	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing hook %s: %v\n", hookPath, err)
		return 2
	}

	fmt.Printf("nox install-hook: wrote %s\n", hookPath)
	fmt.Printf("The hook blocks findings of severity %s or above.\n", threshold)
	fmt.Printf("Skip it once with `git %s --no-verify`.\n", strings.TrimPrefix(hookKind, "pre-"))
	return 0
}
