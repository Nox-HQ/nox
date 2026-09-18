package secrets

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The vendor-keyword family is every rule whose pattern was nothing but a
// character class and a length — `[a-zA-Z0-9]{32}` and relatives — with the
// vendor's name as the only thing tying it to a credential. 151 rules.
//
// Proximity was the first attempt at making that safe: the vendor word had to
// appear within 4 lines and 512 characters of the match. crewAI's recorded
// cassettes showed it was not enough. A Content-Security-Policy response header
// listing CDN domains sat three lines above an HTTP ETag, and five separate
// vendor rules reported that one ETag as their own vendor's credential:
//
//	line 132:   'default-src 'self'; script-src https://cdn.amplitude.com
//	             https://cdn.segment.com https://browser.sentry-cdn.com
//	             https://edge.fullstory.com …'
//	line 136:   - W/"9e9becfaa0607314159093ffcadb0713"
//
// Generalised into the corpus below, 116 of the 151 fired on something that is
// not a credential and never was. The fix is that the vendor name must BIND the
// value through an assignment, not merely be nearby.
//
// These two tests bound the fix from both sides: nothing in ordinary HTTP
// traffic may be read as a credential, and every rule must still report its own
// vendor's bound credential (TestDegenerateRules_StillDetectRealSecrets).

// httpArtifacts are values that appear in real HTTP traffic and are never
// credentials. Each is the right shape to satisfy a generic length pattern,
// which is exactly why the family matched them.
var httpArtifacts = []struct{ name, header, value string }{
	{"weak ETag", "etag", `W/"9e9becfaa0607314159093ffcadb0713"`},
	{"request id", "x-request-id", "1f71464a818066687bf6c1bcae0abb991d6ed9cd"},
	{"trace id", "traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
	{"cache key", "x-cache-key", "abcdefghijklmnopqrstuvwxyz012345"},
	{"CDN request id", "x-amz-cf-id", "AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789"},
	{"session cookie", "set-cookie", "__cf_bm=J_xe1AP.B5P6D2GVMCesyioeS5E9DnYT34rbwQUefFc"},
}

// TestNoVendorRuleReadsHTTPTrafficAsACredential is the false-positive guard for
// the whole family, and the regression test for the cassette defect.
//
// For every bound rule it builds a response in which the vendor is named the
// way HTTP actually names one — in a CSP allow-list, in a `server:` header, in
// a vendor-specific trace header — next to artifacts that are unambiguously not
// credentials. Nothing may be reported.
func TestNoVendorRuleReadsHTTPTrafficAsACredential(t *testing.T) {
	t.Parallel()

	family := degenerateRules(t)
	if len(family) == 0 {
		t.Fatal("no bound vendor rules found; this test's family selection is stale")
	}

	analyzer := NewAnalyzer()
	var offenders []string

	for _, rule := range family {
		vendor := "vendor"
		if len(rule.Keywords) > 0 {
			vendor = rule.Keywords[0]
		}
		var b strings.Builder
		fmt.Fprintf(&b, "interactions:\n- response:\n    headers:\n")
		// The vendor named every way HTTP names one, and never as an assignment
		// of a credential.
		fmt.Fprintf(&b, "      content-security-policy:\n      - 'default-src ''self''; script-src https://cdn.%s.com'\n", vendor)
		fmt.Fprintf(&b, "      server:\n      - %s\n", vendor)
		for _, a := range httpArtifacts {
			fmt.Fprintf(&b, "      %s:\n      - %s\n", a.header, a.value)
		}
		// The vendor's own trace header: the vendor name IS adjacent to a colon
		// here, which is what makes this the sharp case — only refusing to
		// cross the newline keeps it out.
		fmt.Fprintf(&b, "      x-%s-trace-id:\n      - AbCdEf0123456789AbCdEf0123456789\n", vendor)

		matches, err := analyzer.ScanFile("cassette.yaml", []byte(b.String()))
		if err != nil {
			t.Fatalf("%s: scan error: %v", rule.ID, err)
		}
		for i := range matches {
			if matches[i].RuleID == rule.ID {
				offenders = append(offenders, fmt.Sprintf("%s (%s) on %q",
					rule.ID, vendor, truncate(matches[i].Message, 60)))
				break
			}
		}
	}

	if len(offenders) > 0 {
		t.Errorf("%d of %d vendor rules reported ordinary HTTP traffic as a credential. "+
			"A generic token plus vendor text nearby is not evidence of a secret:\n  %s",
			len(offenders), len(family), strings.Join(offenders, "\n  "))
	}
}

// bareShape is the pattern form this family used to have: a character class and
// a length, with no literal of its own.
var bareShape = regexp.MustCompile(`^(\\b)?\[[^\]]+\]\{\d+(,\d*)?\}(\\b)?$`)

// TestEveryVendorKeywordRuleIsBound is the invariant, so the defect cannot
// return by the back door — a new rule added to the table in the old shape.
//
// Any rule may be anchorless OR keyword-gated; none may be a bare shape whose
// only tie to the vendor is a keyword, because that is the combination that
// turns an ETag into a credential.
func TestEveryVendorKeywordRuleIsBound(t *testing.T) {
	t.Parallel()

	var unbound []string
	for _, r := range builtinSecretRules() {
		if r.MatcherType == "entropy" {
			continue // class B: entropy over declared candidate kinds, its own design
		}
		if !bareShape.MatchString(r.Pattern) {
			continue
		}
		if len(r.Keywords) == 0 && len(r.RequireContextKeywords) == 0 {
			continue // no vendor claim to over-extend
		}
		unbound = append(unbound, fmt.Sprintf("%s (%s, keywords %v)", r.ID, r.Pattern, r.Keywords))
	}
	if len(unbound) > 0 {
		t.Errorf("%d rule(s) still match a bare character class gated only by a vendor keyword. "+
			"Bind the vendor name to the value (`<vendor>… = \"<shape>\"`) or give the pattern the "+
			"vendor's real credential format:\n  %s", len(unbound), strings.Join(unbound, "\n  "))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// TestABoundRuleIsNotBlindToTheOtherSpelling is the recall half of the family
// invariant, and it exists because binding alone did not give it.
//
// A rule keyed on the literal `runpod_key` bound that one spelling. Measured
// across seven vendors after the binding landed, `<vendor>_key` was reported
// and `<vendor>_token` and `<vendor>_api_token` were reported by NOTHING --
// not by the vendor's own rule, not by the generic assignment rules. A
// credential does not stop being one because the variable holding it was named
// `token` rather than `key`.
//
// Widening the PATTERN did not fix it either, which is the part worth keeping:
// Keywords gate at file level, so the rule was filtered out before its pattern
// ever ran. Both halves had to move.
func TestABoundRuleIsNotBlindToTheOtherSpelling(t *testing.T) {
	t.Parallel()

	// The token is generated from each rule's OWN shape. A fixed 32-character
	// token reported 21 spellings as uncovered that were nothing of the kind:
	// SEC-479 requires 42 characters and SEC-473 requires 36, so the fixture was
	// too short and the rule was blamed. The same fixture error, in the other
	// direction, earlier reported 29 rules in this family as dead.
	// SEC-510 is excluded, with a reason rather than by convenience. Its stem is
	// `aws`, and AWS credential variables are named by the SDK convention --
	// `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`. The
	// spellings this test generates (`aws_key`, `aws_token`) are not AWS
	// credential names, and the ones that are get reported by the dedicated AWS
	// rules: `aws_secret` here is caught by SEC-081 and SEC-412. Widening `aws`
	// to cover invented spellings would bind a three-letter stem that prefixes a
	// great deal of ordinary configuration.
	skip := map[string]string{
		"SEC-510": "aws: credential names are SDK-conventional; covered by SEC-081/SEC-412",
	}

	analyzer := NewAnalyzer()
	var blind []string

	for _, rule := range degenerateRules(t) {
		if len(rule.Keywords) == 0 {
			continue
		}
		if _, ok := skip[rule.ID]; ok {
			continue
		}
		stem := credentialStem(rule.Keywords[0])
		if stem == "" {
			continue // keyword is already a bare vendor name
		}
		token := realisticSecret(boundShape(rule))
		for _, suffix := range []string{"_key", "_token", "_api_key", "_api_token"} {
			content := fmt.Sprintf("%s%s = %q\n", stem, suffix, token)
			matches, err := analyzer.ScanFile("config.py", []byte(content))
			if err != nil {
				t.Fatalf("%s: %v", rule.ID, err)
			}
			if len(matches) == 0 {
				blind = append(blind, fmt.Sprintf("%s: nothing reports %s%s", rule.ID, stem, suffix))
			}
		}
	}

	if len(blind) > 0 {
		t.Errorf("%d vendor credential spelling(s) are reported by no rule at all:\n  %s",
			len(blind), strings.Join(blind, "\n  "))
	}
}
