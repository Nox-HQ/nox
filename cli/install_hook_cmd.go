package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// runInstallHook installs a git hook that runs `nox scan --staged` (or
// equivalent diff-scoped scan) before commit or push. Operators bypass with
// `--no-verify` as usual; the hook respects that escape hatch.
func runInstallHook(args []string) int {
	fs := flag.NewFlagSet("install-hook", flag.ContinueOnError)
	var (
		repoPath   string
		hookKind   string
		failOn     string
		bin        string
		force      bool
	)
	fs.StringVar(&repoPath, "repo", ".", "path to the git repository")
	fs.StringVar(&hookKind, "kind", "pre-commit", "hook kind: pre-commit or pre-push")
	fs.StringVar(&failOn, "fail-on", "critical,high", "comma-separated severities that fail the hook")
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

	script := renderHookScript(hookKind, bin, failOn)
	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing hook %s: %v\n", hookPath, err)
		return 2
	}

	fmt.Printf("nox install-hook: wrote %s\n", hookPath)
	fmt.Printf("Hook will fail on findings of severity: %s\n", failOn)
	fmt.Println("Bypass with `git commit --no-verify` if needed.")
	return 0
}

// renderHookScript builds the shell script body for a git hook of the
// requested kind. Pre-commit scopes scanning to the staged diff for the
// fastest feedback loop; pre-push scans the full working tree.
func renderHookScript(kind, bin, failOn string) string {
	failOn = strings.TrimSpace(failOn)
	if failOn == "" {
		failOn = "critical,high"
	}

	switch kind {
	case "pre-push":
		return fmt.Sprintf(`#!/usr/bin/env sh
# Installed by `+"`nox install-hook --kind pre-push`"+`. Bypass with --no-verify.
set -e

if ! command -v %[1]s >/dev/null 2>&1; then
  echo "nox: %[1]s not found on PATH; skipping pre-push scan" >&2
  exit 0
fi

%[1]s scan . --severity-threshold "$(echo %[2]s | cut -d, -f1)" --quiet
status=$?
if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
  exit "$status"
fi
exit 0
`, bin, failOn)
	default: // pre-commit
		return fmt.Sprintf(`#!/usr/bin/env sh
# Installed by `+"`nox install-hook --kind pre-commit`"+`. Bypass with --no-verify.
set -e

if ! command -v %[1]s >/dev/null 2>&1; then
  echo "nox: %[1]s not found on PATH; skipping pre-commit scan" >&2
  exit 0
fi

# Only block on staged-file findings. nox scan --staged scopes to the
# index so the hook stays under typical commit latency budgets.
%[1]s scan . --staged --severity-threshold "$(echo %[2]s | cut -d, -f1)" --quiet
status=$?
if [ "$status" -eq 1 ]; then
  echo "nox: pre-commit scan found %[2]s findings — fix and re-stage, or commit --no-verify to bypass" >&2
  exit 1
fi
if [ "$status" -ne 0 ]; then
  exit "$status"
fi
exit 0
`, bin, failOn)
	}
}
