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

// TestAnchorlessRecognisesAnOpenQuantifier is the regression for a guard that
// missed the case it was written for.
//
// isAnchorlessPattern decides whether a vendor rule gets the proximity
// requirement and the secret-shape filter. Its regex required a digit after the
// comma — `(,\d+)?` — so `{32}` and `{32,64}` were recognised and `{32,}` was
// not. The unbounded form is the MOST anchorless a pattern can be, and it was
// the one form the protection skipped: 36 rules, all high severity, none of
// them getting either control.
func TestAnchorlessRecognisesAnOpenQuantifier(t *testing.T) {
	for _, p := range []string{
		`[a-zA-Z0-9]{32}`, `[a-zA-Z0-9]{32,64}`,
		`[a-zA-Z0-9]{32,}`, `[a-zA-Z0-9_-]{50,}`, `[a-zA-Z0-9-]{20,}`,
		`\b[a-f0-9]{40}\b`,
	} {
		if !isAnchorlessPattern(p) {
			t.Errorf("%s is not recognised as anchorless, so it receives neither the "+
				"proximity requirement nor the shape filter — the two controls that "+
				"stop a bare character class matching every long string in a file", p)
		}
	}
	// A pattern carrying real literal text ties itself to the credential
	// format, and must not be treated as anchorless: adding a proximity
	// requirement to it would cost recall for nothing.
	for _, p := range []string{
		`(?i)cloudflare[_-]?api[_-]?token\s*[=:]\s*['"]?[A-Za-z0-9_-]{40}`,
		`ghp_[A-Za-z0-9]{36}`,
		`AKIA[0-9A-Z]{16}`,
	} {
		if isAnchorlessPattern(p) {
			t.Errorf("%s carries literal text and was treated as anchorless", p)
		}
	}
}

// TestEveryAnchorlessRuleGetsBothControls. The protection is applied by a
// derivation rather than declared per rule, so a rule can silently miss it —
// which is exactly what happened. This checks the outcome instead of the
// derivation.
func TestEveryAnchorlessRuleGetsBothControls(t *testing.T) {
	var unprotected []string
	for _, r := range builtinSecretRules() {
		if r.MatcherType != "regex" || !isAnchorlessPattern(r.Pattern) {
			continue
		}
		if len(r.RequireContextKeywords) == 0 && len(r.Keywords) > 0 {
			unprotected = append(unprotected, r.ID)
		}
		if r.Metadata["secret_shape"] != "true" {
			unprotected = append(unprotected, r.ID+" (no shape filter)")
		}
	}
	if len(unprotected) > 0 {
		t.Errorf("%d anchorless rule(s) carry no proximity requirement or shape "+
			"filter: %v. Such a rule means \"this file mentions the vendor and "+
			"contains a long string\", at whatever severity it declares",
			len(unprotected), unprotected)
	}
}
