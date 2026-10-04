package rules

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

func retryRule(pattern string, validate func(string) bool) *Rule {
	return &Rule{
		ID: "TEST-RETRY", Version: "1.0", Description: "retry after a veto",
		Severity: findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
		MatcherType: "regex", Pattern: pattern, ValidateMatch: validate,
	}
}

func scanStarts(t *testing.T, r *Rule, content string) []int {
	t.Helper()
	rs := NewRuleSet()
	rs.Add(r)
	got, err := NewEngine(rs).ScanFile("f.txt", []byte(content))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var cols []int
	for _, f := range got {
		cols = append(cols, f.Location.StartColumn)
	}
	return cols
}

// A match the predicate rejects must not hide a later match that overlaps it.
// FindAll is leftmost and non-overlapping: "kkkz" is the one match, and once
// it is vetoed, "kkz" at column 2 was never tried.
func TestValidateMatch_VetoDoesNotHideAnOverlappingMatch(t *testing.T) {
	r := retryRule(`k+z`, func(m string) bool { return len(m) <= 3 })
	if got := scanStarts(t, r, "kkkz\n"); len(got) != 1 || got[0] != 2 {
		t.Fatalf("want the overlapping match at column 2, got %v", got)
	}
}

// Resuming the scan mid-text must not invent a word boundary: after "abc" is
// vetoed, "bc" starts a resumed slice, where \b would hold if the preceding
// byte were forgotten.
func TestValidateMatch_RetryKeepsBoundaryContext(t *testing.T) {
	r := retryRule(`\b[a-z]+`, func(m string) bool { return m != "abc" })
	if got := scanStarts(t, r, "abc\n"); len(got) != 0 {
		t.Fatalf("a match inside a word is not at a boundary; got columns %v", got)
	}
}

// When every match validates, the matches are exactly FindAll's.
func TestValidateMatch_NoVetoChangesNothing(t *testing.T) {
	r := retryRule(`k+z`, func(string) bool { return true })
	if got := scanStarts(t, r, "kkkz kz\n"); len(got) != 2 || got[0] != 1 || got[1] != 6 {
		t.Fatalf("want FindAll's columns [1 6], got %v", got)
	}
}
