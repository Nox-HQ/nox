package rules

import "testing"

// A reference is not a value.
//
// SEC-161 reported `const apiKey = process.env.ANTHROPIC_MICROSOFT_API_KEY` as
// a high-entropy secret. That line is the remediation the rule recommends --
// "move high-entropy values to environment variables" -- so the rule was
// flagging the fix for the problem it reports. Measured on the pinned corpus,
// 8 of SEC-161's 22 non-test findings were environment-variable reads, and 0
// of the 22 were real secrets.
//
// extractAssignmentRHS already declined `domain.PrePush.ConfigKey()` for the
// right reason: a selector expression has no value at scan time. The trailing
// parens were doing the work; the reasoning never needed them.

func TestAMemberAccessChainIsNotAValue(t *testing.T) {
	m := &EntropyMatcher{}
	rule := &Rule{ID: "TEST-ENT", MatcherType: "entropy",
		Metadata: map[string]string{"entropy_threshold": "3.5", "require_context": "true"}}

	for _, line := range []string{
		"const apiKey = process.env.ANTHROPIC_MICROSOFT_API_KEY;",
		"'x-api-key': sandboxEnvironment.ANTHROPIC_API_KEY,",
		"const chatProxyToken = process.env.GEISTDOCS_CHAT_PROXY_TOKEN;",
		"\t\tForgeKeys:   domain.GitHubWebFlowKeys[:1],",
	} {
		if got := m.Match([]byte(line), rule); len(got) > 0 {
			t.Errorf("matched %q in %q -- that is a reference, and reporting it tells "+
				"the reader to fix code that is already correct", got[0].MatchText, line)
		}
	}
}

// TestAnUnquotedLiteralStillReports is the recall half. The unquoted-RHS
// tokenizer exists for YAML, JSON, .env and INI, where a value legitimately
// carries no quotes. Narrowing must not cost those.
func TestAnUnquotedLiteralStillReports(t *testing.T) {
	m := &EntropyMatcher{}
	rule := &Rule{ID: "TEST-ENT", MatcherType: "entropy",
		Metadata: map[string]string{"entropy_threshold": "3.5", "require_context": "true"}}

	for _, line := range []string{
		"api_key: xK9mR3pZqW7nL2vB8sT4yH6jF0dA5cE1",
		"SECRET_TOKEN=aQ4wE7rT9yU2iO5pA8sD1fG3hJ6kL0zX",
	} {
		if got := m.Match([]byte(line), rule); len(got) == 0 {
			t.Errorf("stopped reporting %q, an unquoted literal value", line)
		}
	}
}

// TestAnUnquotedJWTIsStillAValue is the case the length bound exists for. A JWT
// is dot-separated and its segments are alphanumeric, so a naive "contains
// dots" test would discard it -- and an unquoted JWT in a YAML value is a real
// credential in a real place.
func TestAnUnquotedJWTIsStillAValue(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	if isMemberAccessChain(jwt) {
		t.Error("a JWT was classified as a member-access chain; an unquoted JWT in a " +
			"config value would stop being reported")
	}
	m := &EntropyMatcher{}
	rule := &Rule{ID: "TEST-ENT", MatcherType: "entropy",
		Metadata: map[string]string{"entropy_threshold": "3.5", "require_context": "true"}}
	if got := m.Match([]byte("auth_token: "+jwt), rule); len(got) == 0 {
		t.Error("an unquoted JWT assigned to auth_token is no longer reported")
	}
}

func TestIsMemberAccessChain(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"process.env.API_KEY", true},
		{"sandboxEnvironment.ANTHROPIC_API_KEY", true},
		{"domain.GitHubWebFlowKeys", true},
		{"_private.value", true},
		{"noDotsHere", false},            // single segment
		{"", false},                      // empty
		{"a..b", false},                  // empty segment
		{"9lives.cat", false},            // segment starts with a digit
		{"host.example-site.com", false}, // hyphen is not identifier-shaped
		{"aVeryLongSegmentThatCouldItselfBeACredential123456.x", false}, // >= 32 chars
	} {
		if got := isMemberAccessChain(tc.in); got != tc.want {
			t.Errorf("isMemberAccessChain(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
