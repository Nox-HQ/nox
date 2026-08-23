package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A matcher type that validates at load time but matches nothing at scan time is
// the worst possible combination: the rule loads, `nox rules` lists it, the scan
// runs clean, and the author concludes their rule found nothing. It never ran.
//
// Not registering the type at all is strictly SAFER than registering a stub —
// Engine.Scan returns "no matcher registered for type %q (rule %s)" and the
// failure is loud. A stub converts that loud failure into a silent clean scan,
// which is the one outcome nox must never produce.

// writeRuleFile writes a one-rule YAML file and returns its path.
func writeRuleFile(t *testing.T, matcherType string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	body := "rules:\n" +
		"  - id: TEST-STUB-001\n" +
		"    matcher_type: " + matcherType + "\n" +
		"    pattern: \"$.secrets[*]\"\n" +
		"    severity: high\n" +
		"    confidence: high\n" +
		"    message: a rule the author expects to run\n" +
		"    description: a rule the author expects to run\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing rules: %v", err)
	}
	return path
}

// TestUnimplementedMatcherTypesAreRejectedAtLoadTime pins the contract: a matcher
// type nox cannot actually run must be refused when the rule is loaded, never
// accepted and then quietly ignored.
func TestUnimplementedMatcherTypesAreRejectedAtLoadTime(t *testing.T) {
	for _, mt := range []string{"jsonpath", "yamlpath", "heuristic"} {
		t.Run(mt, func(t *testing.T) {
			if ValidMatcherTypes[mt] {
				t.Errorf("matcher_type %q validates at load time, but no matcher implements it — "+
					"a rule using it loads, lists, and silently matches nothing", mt)
			}
			_, err := LoadRulesFromFile(writeRuleFile(t, mt))
			if err == nil {
				t.Fatalf("a rule with matcher_type %q loaded without error; the author has no way to "+
					"learn their rule will never run", mt)
			}
			if !strings.Contains(err.Error(), mt) {
				t.Errorf("the rejection %q does not name the matcher type that caused it", err)
			}
		})
	}
}

// TestEveryValidMatcherTypeHasARealMatcher is the general form, so a future
// matcher type cannot be added to the validation set before something implements
// it. It also guards the reverse: a registered matcher nobody may reference.
func TestEveryValidMatcherTypeHasARealMatcher(t *testing.T) {
	reg := NewDefaultMatcherRegistry()
	for mt := range ValidMatcherTypes {
		if reg.Get(mt) == nil {
			t.Errorf("matcher_type %q passes validation but has no registered matcher; every rule using "+
				"it fails the scan with \"no matcher registered\"", mt)
		}
	}
	for mt := range reg.matchers {
		if !ValidMatcherTypes[mt] {
			t.Errorf("matcher %q is registered but no rule may declare it; it can never run", mt)
		}
	}
}

// matcherProof is a case that a working matcher of its type MUST match. It is
// what stops the stub from coming back: set membership and non-nil registration
// are both satisfiable by a matcher that returns nil for every input, and that
// is precisely the shape of the bug this file exists for.
type matcherProof struct {
	rule    Rule
	content string
}

// matcherProofs holds one proof case per implemented matcher type. Adding a
// matcher type without a proof case fails TestEveryMatcherTypeProvesItMatches.
var matcherProofs = map[string]matcherProof{
	"regex": {
		rule:    Rule{ID: "PROOF-REGEX", MatcherType: "regex", Pattern: `AKIA[0-9A-Z]{16}`},
		content: "key = AKIAIOSFODNN7EXAMPLE\n",
	},
	"entropy": {
		rule: Rule{
			ID: "PROOF-ENTROPY", MatcherType: "entropy",
			Metadata: map[string]string{"entropy_threshold": "4.0"},
		},
		content: "api_key = \"xQ7fL2mZ9pR4tW8vB3nK6yH1sD5gJ0aC\"\n",
	},
	"absence": {
		rule: Rule{
			ID: "PROOF-ABSENCE", MatcherType: "absence",
			AbsenceAnchor:   `resource "aws_s3_bucket"`,
			AbsenceProperty: `server_side_encryption`,
			AbsenceSpan:     "brace-block",
		},
		content: "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n}\n",
	},
}

// TestEveryMatcherTypeProvesItMatches is the behavioural half of the guard. Each
// implemented matcher type must demonstrate, on a case chosen for it, that it
// can produce a match at all. A matcher that returns nil for every input passes
// every structural check ever written about it; only running it catches that.
func TestEveryMatcherTypeProvesItMatches(t *testing.T) {
	reg := NewDefaultMatcherRegistry()

	for mt := range ValidMatcherTypes {
		proof, ok := matcherProofs[mt]
		if !ok {
			t.Errorf("matcher_type %q is valid but has no proof case; nothing demonstrates it can match "+
				"anything, so a do-nothing matcher would pass every other guard here", mt)
			continue
		}
		m := reg.Get(mt)
		if m == nil {
			continue // already reported by TestEveryValidMatcherTypeHasARealMatcher
		}
		rule := proof.rule
		if got := m.Match([]byte(proof.content), &rule); len(got) == 0 {
			t.Errorf("the %q matcher found nothing in a case built to match it; it is not doing its job, "+
				"and every rule of this type silently reports a clean scan", mt)
		}
	}
	for mt := range matcherProofs {
		if !ValidMatcherTypes[mt] {
			t.Errorf("there is a proof case for matcher_type %q, which no rule may declare", mt)
		}
	}
}
