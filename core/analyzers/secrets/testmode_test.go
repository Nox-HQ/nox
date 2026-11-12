package secrets

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// A key for a vendor's test environment is a real secret, and it is not the
// key to production: a Stripe sk_test_ key moves no money and reads no live
// customer. It was reported exactly as the live key is, critical, first in the
// list. It is kept, at medium, saying which kind of key it is and carrying the
// severity the rule declares.
func TestTestModeKeyIsReportedAsOne(t *testing.T) {
	tests := []struct {
		name, body string
		rules      map[string]findings.Severity // rule -> the rule's own severity
	}{
		{"Stripe secret key",
			"STRIPE_SKEY=sk_test_" + seededBody(21, alnum, 24) + "\n",
			map[string]findings.Severity{"SEC-030": findings.SeverityCritical}},
		{"Stripe restricted key",
			"STRIPE_RKEY=rk_test_" + seededBody(22, alnum, 24) + "\n",
			map[string]findings.Severity{"SEC-030": findings.SeverityCritical, "SEC-338": findings.SeverityHigh}},
		{"Stripe secret key in a string literal",
			"stripe.api_key = \"sk_test_" + seededBody(30, alnum, 24) + "\"\n",
			map[string]findings.Severity{"SEC-030": findings.SeverityCritical}},
		{"Lob key",
			"LOB_API_KEY=test_" + seededBody(24, lowerHex, 35) + "\n",
			map[string]findings.Severity{"SEC-070": findings.SeverityHigh, "SEC-262": findings.SeverityHigh}},
		{"Duffel token",
			"DUFFEL_TOKEN=duffel_test_" + seededBody(27, alnum, 43) + "\n",
			map[string]findings.Severity{"SEC-193": findings.SeverityHigh}},
		{"Shippo token",
			"SHIPPO_TOKEN=shippo_test_" + seededBody(28, lowerHex, 40) + "\n",
			map[string]findings.Severity{"SEC-317": findings.SeverityHigh, "SEC-070": findings.SeverityHigh}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := byRule(t, scanAt(t, ".env", tc.body))
			for rule, ruleSeverity := range tc.rules {
				f, ok := got[rule]
				if !ok {
					t.Errorf("%s reported nothing; a test-mode key is reclassified, never dropped", rule)
					continue
				}
				if f.Severity != findings.SeverityMedium {
					t.Errorf("%s severity = %s, want medium", rule, f.Severity)
				}
				if c := f.Metadata[findings.MetaValueClass]; c != findings.ValueClassTestMode {
					t.Errorf("%s %s = %q, want %q", rule, findings.MetaValueClass, c, findings.ValueClassTestMode)
				}
				if s := f.Metadata[findings.MetaRuleSeverity]; s != string(ruleSeverity) {
					t.Errorf("%s %s = %q, want the rule's own severity %q", rule, findings.MetaRuleSeverity, s, ruleSeverity)
				}
				if !strings.Contains(f.Message, "est-mode") {
					t.Errorf("%s message does not say the key is a test-mode one: %q", rule, f.Message)
				}
				if !f.GatesByDefault() {
					t.Errorf("%s no longer fails a scan; a test-mode key is still a secret in the repository", rule)
				}
			}
			if len(got) != len(tc.rules) {
				t.Errorf("rules reporting = %d, want %d: %v", len(got), len(tc.rules), got)
			}
		})
	}
}

// The counterexamples. A live key of the same vendor keeps the rule's rating,
// and so does a value that merely begins with "test_" under a rule that is not
// the vendor's: "test_" is how Lob marks a test key and how everybody else
// names a test value.
func TestOnlyAVendorsTestKeyIsTestMode(t *testing.T) {
	tests := []struct {
		name, body string
		rule       string
		want       findings.Severity
	}{
		{"Stripe live secret key", "STRIPE_SKEY=sk_live_" + seededBody(41, alnum, 24) + "\n",
			"SEC-030", findings.SeverityCritical},
		{"Stripe live restricted key", "STRIPE_RKEY=rk_live_" + seededBody(42, alnum, 24) + "\n",
			"SEC-030", findings.SeverityCritical},
		{"Lob live key", "LOB_API_KEY=live_" + seededBody(43, lowerHex, 35) + "\n",
			"SEC-262", findings.SeverityHigh},
		{"Duffel live token", "DUFFEL_TOKEN=duffel_live_" + seededBody(44, alnum, 43) + "\n",
			"SEC-193", findings.SeverityHigh},
		{"Shippo live token", "SHIPPO_TOKEN=shippo_live_" + seededBody(45, lowerHex, 40) + "\n",
			"SEC-317", findings.SeverityHigh},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := byRule(t, scanAt(t, ".env", tc.body))[tc.rule]
			if !ok {
				t.Fatalf("%s reported nothing", tc.rule)
			}
			if f.Severity != tc.want {
				t.Errorf("severity = %s, want %s", f.Severity, tc.want)
			}
			if c, ok := f.Metadata[findings.MetaValueClass]; ok {
				t.Errorf("%s = %q on a live key", findings.MetaValueClass, c)
			}
		})
	}
}

// A generic rule's value that starts with "test_" says nothing about any
// vendor's test environment, so no generic finding is reclassified by it.
func TestBareTestPrefixIsNotTestModeOutsideItsVendor(t *testing.T) {
	body := "DB_PASSWORD=\"test_" + seededBody(48, alnum, 30) + "\"\n"
	got := scanAt(t, ".env", body)
	if len(got) == 0 {
		t.Fatal("no rule reported the fixture, so it shows nothing")
	}
	for i := range got {
		if c, ok := got[i].Metadata[findings.MetaValueClass]; ok {
			t.Errorf("%s: %s = %q on a password that only starts with test_", got[i].RuleID, findings.MetaValueClass, c)
		}
	}
}

// A class never raises a rating: a rule that already rates its match below
// medium keeps that rating and still says what the value is.
func TestTestModeNeverRaisesSeverity(t *testing.T) {
	body := []byte("K=sk_test_" + seededBody(49, alnum, 24) + "\n")
	for _, sev := range []findings.Severity{findings.SeverityLow, findings.SeverityInfo, findings.SeverityMedium} {
		f := findings.Finding{RuleID: "SEC-030", Severity: sev, Message: "Stripe API Key detected",
			Location: findings.Location{StartLine: 1, EndLine: 1, StartColumn: 3, EndColumn: 3 + len("sk_test_") + 24}}
		classifyValue(body, &f)
		if f.Severity != sev {
			t.Errorf("rule severity %s became %s", sev, f.Severity)
		}
		if c := f.Metadata[findings.MetaValueClass]; c != findings.ValueClassTestMode {
			t.Errorf("at %s: %s = %q, want %q", sev, findings.MetaValueClass, c, findings.ValueClassTestMode)
		}
	}
}
