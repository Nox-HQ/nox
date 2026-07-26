package rules

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// survivorRule is a rule that absorbed a retired one: same condition, different
// pattern text (the retired rule wrote the colon without optional space).
func survivorRule() *Rule {
	return &Rule{
		ID:          "TEST-SURVIVOR",
		Version:     "1.0",
		Description: "step continues on error",
		Severity:    findings.SeverityLow,
		Confidence:  findings.ConfidenceMedium,
		MatcherType: "regex",
		Pattern:     `(?i)continue-on-error\s*:\s*true`,
		Retires:     []RetiredRule{{ID: "TEST-RETIRED", Pattern: `(?i)continue-on-error:\s*true`}},
	}
}

func scanOne(t *testing.T, rule *Rule, path, content string) findings.Finding {
	t.Helper()
	rs := NewRuleSet()
	rs.Add(rule)
	got, err := NewEngine(rs).ScanFile(path, []byte(content))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding from %s, got %d", rule.ID, len(got))
	}
	return got[0]
}

// TestRetires_AliasFingerprintEqualsTheRetiredRulesOwn is the property the whole
// migration rests on: the alias fingerprint is not merely *a* fingerprint, it is
// byte-for-byte the one the retired rule produced here — which is what a
// committed baseline holds.
func TestRetires_AliasFingerprintEqualsTheRetiredRulesOwn(t *testing.T) {
	const path = ".github/workflows/ci.yml"
	const content = "jobs:\n  test:\n    steps:\n      - continue-on-error: true\n"

	survivor := scanOne(t, survivorRule(), path, content)
	retired := scanOne(t, &Rule{
		ID:          "TEST-RETIRED",
		Version:     "1.0",
		Description: "step continues on error",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceHigh,
		MatcherType: "regex",
		Pattern:     `(?i)continue-on-error:\s*true`,
	}, path, content)

	if len(survivor.AliasFingerprints) != 1 {
		t.Fatalf("AliasFingerprints = %v, want exactly one", survivor.AliasFingerprints)
	}
	if survivor.AliasFingerprints[0] != retired.Fingerprint {
		t.Errorf("alias fingerprint %q != the retired rule's own %q — a baseline entry "+
			"written before the retirement will not match",
			survivor.AliasFingerprints[0], retired.Fingerprint)
	}
	if !survivor.MatchesRuleID("TEST-RETIRED") {
		t.Errorf("RetiredRuleIDs = %v, want it to answer to TEST-RETIRED", survivor.RetiredRuleIDs)
	}
	if survivor.Fingerprint == retired.Fingerprint {
		t.Error("the two fingerprints are equal, so this test proves nothing about aliasing")
	}
}

// TestRetires_DifferentMatchTextStillReproducesTheFingerprint covers the case
// that rules out the naive implementation: IAC-312 matched `set-output name=`
// where the surviving IAC-017 matches `::set-output name=`. Hashing the
// SURVIVOR's matched text under the retired ID would produce a fingerprint that
// never existed.
func TestRetires_DifferentMatchTextStillReproducesTheFingerprint(t *testing.T) {
	const path = ".github/workflows/ci.yml"
	const content = "      - run: echo \"::set-output name=version::1.2.3\"\n"

	survivor := scanOne(t, &Rule{
		ID:          "TEST-SETOUTPUT",
		Version:     "1.0",
		Description: "deprecated set-output",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceHigh,
		MatcherType: "regex",
		Pattern:     `(?i)::set-output\s+name=`,
		Retires:     []RetiredRule{{ID: "TEST-SETOUTPUT-OLD", Pattern: `(?i)set-output\s+name=`}},
	}, path, content)

	retired := scanOne(t, &Rule{
		ID:          "TEST-SETOUTPUT-OLD",
		Version:     "1.0",
		Description: "deprecated set-output",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceHigh,
		MatcherType: "regex",
		Pattern:     `(?i)set-output\s+name=`,
	}, path, content)

	if len(survivor.AliasFingerprints) != 1 || survivor.AliasFingerprints[0] != retired.Fingerprint {
		t.Errorf("alias fingerprints %v do not include the retired rule's own %q; the two rules "+
			"matched different text (%q vs %q), which is exactly the case a naive alias gets wrong",
			survivor.AliasFingerprints, retired.Fingerprint, "::set-output name=", "set-output name=")
	}
}

// TestRetires_NoAliasWhereTheRetiredRuleWouldNotHaveFired keeps an ID-level
// waiver from widening. The survivor matches `continue-on-error : true` (space
// before the colon); the retired rule did not, so nothing about that line was
// ever waived under the retired ID.
func TestRetires_NoAliasWhereTheRetiredRuleWouldNotHaveFired(t *testing.T) {
	f := scanOne(t, survivorRule(), "ci.yml", "      - continue-on-error : true\n")

	if len(f.RetiredRuleIDs) != 0 || len(f.AliasFingerprints) != 0 {
		t.Errorf("finding inherited %v / %v on a line the retired rule never matched — "+
			"a waiver for the retired ID would now suppress a condition it never covered",
			f.RetiredRuleIDs, f.AliasFingerprints)
	}
}

// TestRetires_UncompilablePatternIsInert: a broken retirement pattern costs the
// alias, not the finding.
func TestRetires_UncompilablePatternIsInert(t *testing.T) {
	rule := survivorRule()
	rule.Retires = []RetiredRule{{ID: "TEST-RETIRED", Pattern: `(?!nope)`}}

	f := scanOne(t, rule, "ci.yml", "      - continue-on-error: true\n")
	if len(f.AliasFingerprints) != 0 {
		t.Errorf("AliasFingerprints = %v, want none", f.AliasFingerprints)
	}
	if f.Fingerprint == "" {
		t.Error("the finding lost its own fingerprint")
	}
}

// TestRetires_UnrelatedRuleIsUnaffected: findings from rules that retire nothing
// carry no alias fields, so the JSON artifact and the cache are unchanged for
// every rule but the handful that absorbed an ID.
func TestRetires_UnrelatedRuleIsUnaffected(t *testing.T) {
	rule := survivorRule()
	rule.Retires = nil

	f := scanOne(t, rule, "ci.yml", "      - continue-on-error: true\n")
	if f.RetiredRuleIDs != nil || f.AliasFingerprints != nil {
		t.Errorf("RetiredRuleIDs=%v AliasFingerprints=%v, want both nil",
			f.RetiredRuleIDs, f.AliasFingerprints)
	}
}
