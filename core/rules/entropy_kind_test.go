package rules

import (
	"strings"
	"testing"
)

// SEC-161/162/163 are three descriptions over one detection. They all use
// EntropyMatcher, which ran every tokenizer regardless of which rule was
// asking, so the rule ID attached to a finding said what the RULE is called,
// not what the candidate actually is.
//
// Reported as issue #467: SEC-163 ("High-entropy hex string detected") fired on
// `domain.GitHubWebFlowKeys` — an identifier containing no hex.
//
// The reporter also observed that the 40-character hex literals the identifier
// names produced no finding. That half is CORRECT and deliberate:
// isLikelyNotSecret excludes exactly-40-hex strings as git commit SHAs, and the
// literals in question are public GPG fingerprints. Only the false positive is
// a defect.
//
// The arithmetic makes it structural rather than unlucky: Shannon entropy over a
// 16-symbol alphabet cannot exceed log2(16) = 4.0 bits per character, and
// SEC-163 asked for 4.5 (4.0 with the context boost). The rule named for hex
// could never match hex, and could only match candidates drawn from a richer
// alphabet — the things it is not looking for. See the companion test in
// core/analyzers/secrets for the shipped rules' side of this.

// hexRule builds a hex-scoped entropy rule at the given threshold.
func hexRule(threshold string) *Rule {
	return &Rule{
		ID: "TEST-HEX", MatcherType: "entropy",
		Metadata: map[string]string{
			"entropy_threshold": threshold,
			"require_context":   "true",
			"candidate_kinds":   string(candidateHex),
		},
	}
}

// TestAHexStringCannotExceedFourBitsPerCharacter states the bound the fix rests
// on, so it is measured rather than asserted.
func TestAHexStringCannotExceedFourBitsPerCharacter(t *testing.T) {
	uniform := strings.Repeat("0123456789abcdef", 8)
	if got := ShannonEntropy(uniform); got > 4.0+1e-9 {
		t.Fatalf("a uniform hex string measured %.4f bits/char, above the 4.0 ceiling the "+
			"kind-scoped thresholds are chosen against", got)
	}
	// A real hex key sits below the ceiling, which is why a threshold at or
	// above 4.0 disables the rule outright rather than merely tightening it.
	key := "a3f1c92e7b04d85fa61c30be97d24f08e5b"
	if got := ShannonEntropy(key); got >= 4.0 {
		t.Fatalf("expected a real hex key below the ceiling, got %.4f", got)
	}
}

// TestEntropyRuleMatchesOnlyItsDeclaredKind is the fix's contract: a rule that
// declares it detects hex is not offered candidates the other tokenizers found.
func TestEntropyRuleMatchesOnlyItsDeclaredKind(t *testing.T) {
	m := &EntropyMatcher{}

	// The exact line from issue #467. No hex anywhere on it.
	const useSite = "\t\tForgeKeys:   domain.GitHubWebFlowKeys[:1],"
	// A 34-character hex secret. Deliberately not 40, 64 or 128 characters:
	// isLikelyNotSecret excludes those three lengths as SHA-1/256/512 digests,
	// which is why the 40-char fingerprints in #467 are correctly unreported.
	const defSite = "\tsigningKey := \"a3f1c92e7b04d85fa61c30be97d24f08e5b\""

	t.Run("a hex-scoped rule ignores a line with no hex", func(t *testing.T) {
		if got := m.Match([]byte(useSite), hexRule("3.5")); len(got) > 0 {
			t.Errorf("a hex-scoped rule matched %q on a line containing no hex string", got[0].MatchText)
		}
	})

	t.Run("a hex-scoped rule still matches actual hex", func(t *testing.T) {
		got := m.Match([]byte(defSite), hexRule("3.5"))
		if len(got) == 0 {
			t.Fatal("a hex-scoped rule found nothing in a hex key on a line naming it " +
				"a signing key; the rule still cannot detect what it is named for")
		}
		for _, r := range got {
			if !isHexString(r.MatchText) {
				t.Errorf("a hex-scoped rule matched %q, which is not hex", r.MatchText)
			}
		}
	})

	t.Run("an unscoped rule keeps the previous behaviour", func(t *testing.T) {
		// Rules that declare no kinds must be unaffected, or this change would
		// silently alter every other entropy rule in the catalogue.
		unscoped := &Rule{ID: "TEST-ANY", MatcherType: "entropy",
			Metadata: map[string]string{"entropy_threshold": "3.5", "require_context": "true"}}
		if got := m.Match([]byte(useSite), unscoped); len(got) == 0 {
			t.Error("an unscoped entropy rule stopped matching what it used to match")
		}
	})

	t.Run("overlapping tokenizers do not steal each other's candidates", func(t *testing.T) {
		// `secret_key = xK9mR3pZ...` is BOTH an assignment RHS and a
		// base64-shaped blob. Both descriptions are true, so a candidate carries
		// the set of kinds that found it. If it carried only one, whichever
		// tokenizer ran first would silently disable the rules scoped to the
		// others — which is what a single-kind draft of this change did to
		// SEC-161, caught by the shipped positive-example test.
		const both = "\tsecret_key = xK9mR3pZ7wL2jY5nQ8vB4fH1cT6gD0sA"
		assignment := &Rule{ID: "TEST-ASSIGN", MatcherType: "entropy",
			Metadata: map[string]string{"entropy_threshold": "4.0",
				"candidate_kinds": string(candidateAssignment) + "," + string(candidateQuoted)}}
		b64 := &Rule{ID: "TEST-B64", MatcherType: "entropy",
			Metadata: map[string]string{"entropy_threshold": "4.0",
				"candidate_kinds": string(candidateBase64)}}
		if got := m.Match([]byte(both), assignment); len(got) == 0 {
			t.Error("an assignment-scoped rule missed an assignment RHS that is also base64-shaped")
		}
		if got := m.Match([]byte(both), b64); len(got) == 0 {
			t.Error("a base64-scoped rule missed a base64-shaped blob that is also an assignment RHS")
		}
	})
}

// isHexString reports whether s is entirely hex digits.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
