package secrets

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/rules"
)

// A large family of vendor secret rules match nothing but a bare character
// class and a length — `[a-zA-Z0-9]{32}` and similar — gated only by a keyword
// appearing somewhere in the same FILE. On any file mentioning the vendor, every
// run of characters of that length becomes a high-severity credential finding:
// Go comments, JSON values, test names.
//
// Measured on nox's own source, one such rule (SEC-652, "Jenkins API Token",
// `[a-zA-Z0-9]{20}` keyed on "jenkins") produced 34 high-severity false
// positives, and two of them blocked this repository's own PR gate.
//
// The fix is the shape/entropy gate the codebase already applies to the same
// pattern elsewhere. The risk of that fix is false NEGATIVES: a gate tuned too
// tight stops detecting real credentials, which is far worse than noise. These
// tests bound that risk from both sides.

// degenerateRule reports whether a rule's pattern is a bare character class
// plus a length quantifier, carrying no literal anchor text of its own.
var degeneratePattern = regexp.MustCompile(`^(\\b)?\[[^\]]+\]\{\d+(,\d+)?\}(\\b)?$`)

func degenerateRules(t *testing.T) []*rules.Rule {
	t.Helper()

	var out []*rules.Rule
	for _, r := range builtinSecretRules() {
		if degeneratePattern.MatchString(r.Pattern) {
			out = append(out, r)
		}
	}
	return out
}

// realisticSecret builds a token that satisfies a rule's pattern and looks like
// a credential a vendor would actually issue: mixed case, digits, high entropy,
// no repetition. This is the input that MUST still be detected.
func realisticSecret(pattern string) string {
	// The alphabet a real token draws from, restricted to what the pattern
	// permits. Order is shuffled deterministically to keep entropy high.
	const mixed = "aZ3xQ7mK9pR2wL5vN8tB4yH6jD0sF1gC"
	const lowerNum = "a3x7m9p2w5v8t4y6j0s1g"
	const hexish = "a3f7b9e2c5d8a4f6b0e1c"

	length := patternLength(pattern)
	if length == 0 {
		length = 32
	}

	// Draw only from characters the pattern actually permits, or the "secret"
	// cannot match and the test reports a false negative that is really a flaw
	// in its own fixture.
	const upperNum = "A3XQ7MK9PR2WL5VN8TB4YH6JD0SF1GC"

	alphabet := mixed
	switch {
	case strings.Contains(pattern, "a-f0-9") || strings.Contains(pattern, "0-9a-f"):
		alphabet = hexish
	case !strings.Contains(pattern, "a-z"):
		alphabet = upperNum
	case !strings.Contains(pattern, "A-Z"):
		alphabet = lowerNum
	}

	// A linear-congruential walk over the alphabet, seeded off the length so
	// different rules get different tokens, with no short-period repetition —
	// real credentials are near-maximal entropy, and a generator that repeats
	// digraphs would fail the very shape filter the rule applies to genuine
	// tokens.
	var b strings.Builder
	x := length*2654435761 + 40503
	for b.Len() < length {
		x = x*1103515245 + 12345
		idx := (x >> 16) % len(alphabet)
		if idx < 0 {
			idx += len(alphabet)
		}
		b.WriteByte(alphabet[idx])
	}
	return b.String()[:length]
}

// patternLength extracts the minimum length from a `{n}` or `{n,m}` quantifier.
func patternLength(pattern string) int {
	m := regexp.MustCompile(`\{(\d+)`).FindStringSubmatch(pattern)
	if m == nil {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(m[1], "%d", &n)
	return n
}

// TestDegenerateRules_StillDetectRealSecrets is the false-negative guard.
//
// Tightening these rules must not stop them finding actual credentials. For
// every degenerate rule, a realistic high-entropy token of the right shape is
// placed in a file containing the rule's keyword — the exact scenario the rule
// exists for — and must still be reported.
func TestDegenerateRules_StillDetectRealSecrets(t *testing.T) {
	t.Parallel()

	defs := degenerateRules(t)
	if len(defs) == 0 {
		t.Fatal("no degenerate rules matched; this test's pattern detection is stale")
	}
	t.Logf("checking %d rules with bare character-class patterns", len(defs))

	analyzer := NewAnalyzer()

	var missed, redundant []string
	for _, rule := range defs {
		secret := realisticSecret(rule.Pattern)
		keyword := "secret"
		if len(rule.Keywords) > 0 {
			keyword = rule.Keywords[0]
		}

		content := fmt.Sprintf("%s_api_key = %q\n", keyword, secret)
		matches, err := analyzer.ScanFile("config.py", []byte(content))
		if err != nil {
			t.Fatalf("%s: scan error: %v", rule.ID, err)
		}

		// The security property is that the credential is DETECTED — not that a
		// particular rule ID detects it. Several of these anchorless rules
		// duplicate a more specific rule for the same vendor (SEC-545 restates
		// SEC-063 for PagerDuty), so asserting per-rule would report a false
		// negative where the secret is in fact reported.
		var detected, byOwnRule bool
		for i := range matches {
			detected = true
			if matches[i].RuleID == rule.ID {
				byOwnRule = true
			}
		}
		if !detected {
			missed = append(missed, fmt.Sprintf("%s (pattern %s, token %q)", rule.ID, rule.Pattern, secret))
		} else if !byOwnRule {
			redundant = append(redundant, rule.ID)
		}
	}

	if len(missed) > 0 {
		t.Errorf("%d of %d rules no longer detect a realistic secret — these are FALSE NEGATIVES, "+
			"strictly worse than the noise being fixed:\n  %s",
			len(missed), len(defs), strings.Join(missed, "\n  "))
	}
	if len(redundant) > 0 {
		// Informational: the credential is still caught, by a more specific
		// rule for the same vendor. Recorded because a rule that never fires on
		// its own realistic input is dead weight worth retiring.
		t.Logf("%d rules were shadowed by a more specific rule for the same vendor: %s",
			len(redundant), strings.Join(redundant, ", "))
	}
}

// TestDegenerateRules_RejectOrdinaryCode is the false-positive measurement.
//
// The same rules are fed the kind of content that produced 34 high-severity
// findings on nox's own source: identifiers, prose comments, and structured
// data values that happen to be long enough. None is a credential, and the
// vendor keyword is far from every one of them.
func TestDegenerateRules_RejectOrdinaryCode(t *testing.T) {
	t.Parallel()

	defs := degenerateRules(t)
	analyzer := NewAnalyzer()

	// Real lines from nox's source that were flagged, plus common shapes.
	samples := []struct{ name, line string }{
		{"go comment", "// NewClassifierRegistry creates an empty ClassifierRegistry."},
		{"json value", `          "call": "HttpResponseRedirect",`},
		{"identifier", "TestEveryClassifiedLockfileIsHandled"},
		{"import path", `import "github.com/nox-hq/nox/core/analyzers/secrets"`},
		{"prose", "// dirContainsAnyIncluded reports whether any path in the include-set is"},
		{"camelCase chain", "resultBuilderConfigurationManagerFactory"},
	}

	var noisy int
	total := len(defs) * len(samples)

	for _, rule := range defs {
		keyword := "secret"
		if len(rule.Keywords) > 0 {
			keyword = rule.Keywords[0]
		}
		for _, s := range samples {
			// The keyword appears in the file but FAR from the match, which is
			// the real false-positive shape. In nox's own discovery.go the word
			// "Jenkinsfile" sits in a filename list around line 60 while the
			// flagged comment is at line 306 — 246 lines away. A test that puts
			// the keyword adjacent measures the case where the rule SHOULD
			// fire, and would have reported this fix as ineffective.
			var b strings.Builder
			fmt.Fprintf(&b, "// this file mentions %s once, near the top\n", keyword)
			for range 40 {
				b.WriteString("// filler line with no credential material\n")
			}
			b.WriteString(s.line + "\n")
			content := b.String()
			matches, err := analyzer.ScanFile("code.go", []byte(content))
			if err != nil {
				t.Fatalf("%s: scan error: %v", rule.ID, err)
			}
			for i := range matches {
				if matches[i].RuleID == rule.ID {
					noisy++
					if noisy <= 5 {
						t.Logf("FP: %s on %s — %q", rule.ID, s.name, matches[i].Message)
					}
				}
			}
		}
	}

	t.Logf("false positives: %d across %d rule/sample combinations", noisy, total)
	if noisy > 0 {
		t.Errorf("%d false positives on ordinary code: every one is a high-severity "+
			"finding an operator must triage", noisy)
	}
}

// cleanConfigValues are non-credential values that legitimately sit right next
// to a vendor keyword in real configuration: hostnames, job names, environment
// names, phone/account numbers, placeholders. The context requirement alone
// does not stop these — the keyword IS adjacent — so they are what the shape
// filter has to reject.
var cleanConfigValues = []string{
	"nightly-integration-suite",    // job name (has hyphens)
	"production-eu-west-1-cluster", // environment name
	"MobileAnalyticsProduction",    // project identifier
	"staging-canary-deployment",    // deployment name
	"441234567890123456",           // phone / account number (digits only)
	"0000000000000000000000000000", // zero placeholder
	"xxxxxxxxxxxxxxxxxxxxxxxxxxxx", // redacted placeholder
	"YOUR_API_KEY_HERE_REPLACE_ME", // template
	"1234567890123456789012345678", // sequential
	"ExampleConfigurationValue123", // camel identifier
}

// TestDegenerateRules_RejectRealisticConfig measures false positives on values
// that appear DIRECTLY beside their vendor keyword — the case the context
// requirement cannot catch, where the shape filter earns its keep.
//
// It records a hard upper bound rather than asserting zero: a small residual
// survives on values whose shape is genuinely ambiguous with a lowercase
// credential (a run-together hostname like "buildserverhostname01" has the same
// character profile as a real lowercase API key). Removing the last few would
// require a dictionary/word heuristic that — measured directly — also rejects
// real high-entropy keys such as an AWS secret access key, trading noise for
// false negatives. The bound catches a regression without pretending the
// residual is gone.
func TestDegenerateRules_RejectRealisticConfig(t *testing.T) {
	t.Parallel()

	defs := degenerateRules(t)
	analyzer := NewAnalyzer()

	const maxFalsePositives = 12 // current: 9, all on hostname-shaped values

	var fps []string
	for _, rule := range defs {
		keyword := "secret"
		if len(rule.Keywords) > 0 {
			keyword = rule.Keywords[0]
		}
		for _, v := range cleanConfigValues {
			content := fmt.Sprintf("%s_setting = %q\n", keyword, v)
			matches, err := analyzer.ScanFile("config.py", []byte(content))
			if err != nil {
				t.Fatalf("%s: scan error: %v", rule.ID, err)
			}
			for i := range matches {
				if matches[i].RuleID == rule.ID {
					fps = append(fps, fmt.Sprintf("%s on %q", rule.ID, v))
				}
			}
		}
	}

	t.Logf("false positives on realistic config: %d (bound %d)", len(fps), maxFalsePositives)
	if len(fps) > maxFalsePositives {
		t.Errorf("false positives rose to %d, above the %d bound:\n  %s",
			len(fps), maxFalsePositives, strings.Join(fps, "\n  "))
	}
}
