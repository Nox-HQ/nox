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
