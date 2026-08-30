package secrets

import "testing"

// TestToolStateDirectoriesAreSkippedAtAnyDepth is the regression for a
// self-inflicted false positive found by scanning real repositories.
//
// generatedFileIgnorePatterns names tool-state directories — .nox, .claude,
// .roady and the rest — and the intent is that nothing inside them is scanned.
// filepath.Match cannot express that: its "*" does not cross a separator and
// the pattern is anchored at the start, so ".claude/*" excluded
// .claude/settings.json and missed .claude/worktrees/agent-x/.nox/baseline.json
// completely.
//
// Measured on a repository with git worktrees under .claude/: 107
// high-severity "Cloudflare API Token" findings, every one a SHA-256
// fingerprint inside nox's OWN baseline files. The tool reported its own
// output as credentials, in a directory the exclusion list already named.
// Removing it took that repository from 311 active findings to 195.
func TestToolStateDirectoriesAreSkippedAtAnyDepth(t *testing.T) {
	skipped := []string{
		".nox/baseline.json",
		"sub/.nox/baseline.json",
		".claude/worktrees/agent-x/.nox/baseline.json",
		"packages/api/.roady/spec.yaml",
		"a/b/c/.cursor/state.json",
		"vendor/thing/testdata/fixture.json",
	}
	for _, p := range skipped {
		if !isGeneratedSecretsPath(p) {
			t.Errorf("%s is scanned; it sits inside a tool-state directory the "+
				"exclusion list already names, so nox reports its own artifacts "+
				"as findings", p)
		}
	}

	// The exclusion must stay about directories. A file that merely shares a
	// name with something in a tool-state directory is ordinary source, and
	// skipping it would hide real credentials.
	scanned := []string{
		"baseline.json",
		"sub/baseline.json",
		"app/config.py",
		"noxious/main.go",       // not .nox
		"claudette/settings.go", // not .claude
	}
	for _, p := range scanned {
		if isGeneratedSecretsPath(p) {
			t.Errorf("%s is skipped; it is not inside a tool-state directory, and "+
				"excluding ordinary source is how a scanner misses a real secret", p)
		}
	}
}
