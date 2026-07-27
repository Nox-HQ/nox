package rules

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// validateMatchRule builds a rule that matches any dotted quad and vetoes
// matches through the supplied predicate.
func validateMatchRule(validate func(string) bool) *Rule {
	return &Rule{
		ID:            "TEST-VALIDATE",
		Version:       "1.0",
		Description:   "test rule with a post-match predicate",
		Severity:      findings.SeverityMedium,
		Confidence:    findings.ConfidenceMedium,
		MatcherType:   "regex",
		Pattern:       `\b[0-9]{1,3}(?:\.[0-9]{1,3}){3}\b`,
		ValidateMatch: validate,
	}
}

// TestValidateMatch_NilKeepsEveryMatch is the control: a rule without a
// predicate behaves exactly as before the hook existed.
func TestValidateMatch_NilKeepsEveryMatch(t *testing.T) {
	rs := NewRuleSet()
	rs.Add(validateMatchRule(nil))

	got, err := NewEngine(rs).ScanFile("config.yaml", []byte("a = 1.2.3.4\nb = 10.0.0.1\n"))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("nil ValidateMatch must keep every match: got %d findings, want 2", len(got))
	}
}

// TestValidateMatch_VetoesRejectedMatches asserts the engine drops exactly the
// matches the predicate rejects and keeps the rest — a rule can raise its
// precision without losing recall on the matches it still accepts.
func TestValidateMatch_VetoesRejectedMatches(t *testing.T) {
	rs := NewRuleSet()
	rs.Add(validateMatchRule(func(m string) bool { return !strings.HasPrefix(m, "10.") }))

	got, err := NewEngine(rs).ScanFile("config.yaml", []byte("a = 1.2.3.4\nb = 10.0.0.1\n"))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Location.StartLine != 1 {
		t.Fatalf("the surviving finding must be the accepted match on line 1, got line %d", got[0].Location.StartLine)
	}
}

// TestValidateMatch_ReceivesMatchTextOnly pins the predicate's contract: it
// sees the matched text and nothing else, so it stays a pure function of the
// match and cannot come to depend on file or line state.
func TestValidateMatch_ReceivesMatchTextOnly(t *testing.T) {
	var seen []string
	rs := NewRuleSet()
	rs.Add(validateMatchRule(func(m string) bool {
		seen = append(seen, m)
		return true
	}))

	if _, err := NewEngine(rs).ScanFile("config.yaml", []byte("a = 1.2.3.4\nb = 10.0.0.1\n")); err != nil {
		t.Fatalf("scan error: %v", err)
	}
	want := []string{"1.2.3.4", "10.0.0.1"}
	if len(seen) != len(want) {
		t.Fatalf("predicate saw %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("predicate saw %v, want %v", seen, want)
		}
	}
}
