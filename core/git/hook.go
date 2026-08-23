package git

import (
	"os"
	"path/filepath"
	"strings"
)

// HookMarker is the line nox writes into a pre-commit hook it generates, so
// install, status, and uninstall can all recognise a nox-owned hook.
//
// It is ONE constant on purpose. It was declared as two independent string
// literals (in the CLI and the MCP server) plus embedded a third time in the
// hook generator, so changing the hook header in one place would silently make
// another's status detection report "not installed by nox" — a marker that only
// works by three copies agreeing by luck.
const HookMarker = "Installed by nox protect"

// PreCommitHookPath returns the path to a repo's pre-commit hook.
func PreCommitHookPath(repoRoot string) string {
	return filepath.Join(repoRoot, ".git", "hooks", "pre-commit")
}

// HookState is the tri-state a pre-commit hook can be in from nox's view.
type HookState int

// Hook states.
const (
	// HookNone — no pre-commit hook exists.
	HookNone HookState = iota
	// HookNox — a pre-commit hook exists and carries nox's marker.
	HookNox
	// HookForeign — a pre-commit hook exists but nox did not install it.
	HookForeign
)

// HookStatus reports whether a repo's pre-commit hook is installed by nox,
// installed by something else, or absent, and the hook path. Both the CLI
// `protect status` and the MCP protect_status tool project from this, so the two
// cannot disagree about a repo's protection state.
func HookStatus(repoRoot string) (state HookState, hookPath string) {
	hookPath = PreCommitHookPath(repoRoot)
	content, err := os.ReadFile(hookPath) //nolint:gosec // path derived from repo root
	if err != nil {
		return HookNone, hookPath
	}
	if strings.Contains(string(content), HookMarker) {
		return HookNox, hookPath
	}
	return HookForeign, hookPath
}
