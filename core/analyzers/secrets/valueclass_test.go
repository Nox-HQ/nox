package secrets

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

const (
	base32Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	base64Body  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lowerHex    = "0123456789abcdef"
)

// byRule indexes a scan's findings by rule, failing on a rule that reported
// more than once so a test reads one finding per rule.
func byRule(t *testing.T, ff []findings.Finding) map[string]findings.Finding {
	t.Helper()
	out := map[string]findings.Finding{}
	for i := range ff {
		if _, dup := out[ff[i].RuleID]; dup {
			t.Fatalf("%s reported twice; the fixture holds one value", ff[i].RuleID)
		}
		out[ff[i].RuleID] = ff[i]
	}
	return out
}

// Stripe's documented sample test keys, built from parts. Written whole they
// are what a secret scanner, GitHub's push protection among them, reads as a
// Stripe key being committed. They are public; only the scan input needs them
// in one piece.
const (
	stripeAPIReferenceKey = "sk_" + "test_" + "BQokikJOvBiI2HlWgH4olfQ2"
	stripeQuickstartBody  = "4eC39HqLyjWDarjtT1zdp7dc"
	stripeQuickstartKey   = "sk_" + "test_" + stripeQuickstartBody
)

// The table is keyed by digest, so nothing but this test shows which values
// it holds. Each documented value must be in it, under what it is, and nothing
// else may be: a digest nobody can name is a value nobody checked.
func TestPublishedValuesAreTheDocumentedOnes(t *testing.T) {
	documented := map[string]string{
		"AKIAIOSFODNN7EXAMPLE":                     "AWS's published example access key ID",
		"AKIAI44QH8DHBEXAMPLE":                     "AWS's published example access key ID",
		"ASIAIOSFODNN7EXAMPLE":                     "AWS's published example temporary access key ID",
		"ASIAI44QH8DHBEXAMPLE":                     "AWS's published example temporary access key ID",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "AWS's published example secret access key",
		"je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY": "AWS's published example secret access key",
		stripeAPIReferenceKey:                      "Stripe's published sample test key",
		stripeQuickstartKey:                        "Stripe's published sample test key",
	}
	for value, what := range documented {
		if got, ok := publishedValueOf(value); !ok || got != what {
			t.Errorf("%.12s…: got (%q, %v), want %q", value, got, ok, what)
		}
	}
	if len(publishedValues) != len(documented) {
		t.Errorf("the table holds %d values, the documentation %d", len(publishedValues), len(documented))
	}
}

// The values below are the ones AWS and Stripe print in their own
// documentation. They authenticate nothing, and a README that copies the
// vendor's example was reported as a leaked critical credential, first in the
// list of issues needing attention. They are reported as what they are: kept,
// at info, saying so, and carrying the severity the rule would have given.
func TestPublishedExampleIsReportedAsWhatItIs(t *testing.T) {
	tests := []struct {
		name, file, body string
		rules            map[string]findings.Severity // rule -> the rule's own severity
	}{
		{"AWS default profile access key", "README.md",
			"    aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n",
			map[string]findings.Severity{"SEC-001": findings.SeverityHigh, "SEC-508": findings.SeverityHigh}},
		{"AWS default profile secret key", "README.md",
			"    aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
			map[string]findings.Severity{"SEC-002": findings.SeverityCritical}},
		{"AWS second profile access key", "docs/setup.rst",
			"   aws_access_key_id = AKIAI44QH8DHBEXAMPLE\n",
			map[string]findings.Severity{"SEC-508": findings.SeverityHigh}},
		{"AWS second profile secret key", "docs/setup.rst",
			"   aws_secret_access_key = \"je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\"\n",
			map[string]findings.Severity{"SEC-002": findings.SeverityCritical}},
		{"Stripe API reference key", ".env.example",
			"STRIPE_SKEY=" + stripeAPIReferenceKey + "\n",
			map[string]findings.Severity{"SEC-030": findings.SeverityCritical}},
		{"Stripe quickstart key", "server.js",
			"const stripe = require('stripe')('" + stripeQuickstartKey + "');\n",
			map[string]findings.Severity{"SEC-030": findings.SeverityCritical}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := byRule(t, scanAt(t, tc.file, tc.body))
			for rule, ruleSeverity := range tc.rules {
				f, ok := got[rule]
				if !ok {
					t.Errorf("%s reported nothing; a published example is reclassified, never dropped", rule)
					continue
				}
				if f.Severity != findings.SeverityInfo {
					t.Errorf("%s severity = %s, want info", rule, f.Severity)
				}
				if c := f.Metadata[findings.MetaValueClass]; c != findings.ValueClassPublishedExample {
					t.Errorf("%s %s = %q, want %q", rule, findings.MetaValueClass, c, findings.ValueClassPublishedExample)
				}
				if s := f.Metadata[findings.MetaRuleSeverity]; s != string(ruleSeverity) {
					t.Errorf("%s %s = %q, want the rule's own severity %q", rule, findings.MetaRuleSeverity, s, ruleSeverity)
				}
				if !strings.Contains(f.Message, "published") || !strings.Contains(f.Message, "not a credential") {
					t.Errorf("%s message does not say what the value is: %q", rule, f.Message)
				}
			}
			if len(got) != len(tc.rules) {
				t.Errorf("rules reporting = %d, want %d: %v", len(got), len(tc.rules), got)
			}
		})
	}
}

// The counterexample: a key of the same shape that no vendor published keeps
// the rule's severity and carries no class. Generated, never written by hand,
// so the value is random enough to be one.
func TestSameShapeKeyKeepsItsSeverity(t *testing.T) {
	tests := []struct {
		name, file, body string
		rule             string
		want             findings.Severity
	}{
		{"AWS access key", "README.md",
			"    aws_access_key_id=AKIA" + seededBody(11, base32Upper, 16) + "\n",
			"SEC-001", findings.SeverityHigh},
		{"AWS secret key", "README.md",
			"    aws_secret_access_key=" + seededBody(12, base64Body, 40) + "\n",
			"SEC-002", findings.SeverityCritical},
		{"Stripe live key", ".env.example",
			"STRIPE_SKEY=sk_live_" + seededBody(13, alnum, 24) + "\n",
			"SEC-030", findings.SeverityCritical},
		// SEC-002 takes exactly 40 characters after the binding, so it matches
		// the first 40 of a longer run. Those 40 being the example does not
		// make the longer value one.
		{"a longer run that begins with AWS's example secret", "deploy.sh",
			"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" + seededBody(16, base64Body, 4) + "\n",
			"SEC-002", findings.SeverityCritical},
		{"AWS's example secret continued by a separator", "deploy.sh",
			"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY/" + seededBody(17, base64Body, 3) + "\n",
			"SEC-002", findings.SeverityCritical},
		{"a longer key that begins with Stripe's example", ".env.example",
			"STRIPE_SKEY=sk_" + "live_" + stripeQuickstartBody + seededBody(14, alnum, 6) + "\n",
			"SEC-030", findings.SeverityCritical},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := byRule(t, scanAt(t, tc.file, tc.body))[tc.rule]
			if !ok {
				t.Fatalf("%s reported nothing", tc.rule)
			}
			if f.Severity != tc.want {
				t.Errorf("severity = %s, want %s", f.Severity, tc.want)
			}
			if c, ok := f.Metadata[findings.MetaValueClass]; ok {
				t.Errorf("%s = %q on a value nobody published", findings.MetaValueClass, c)
			}
		})
	}
}

// A published example on the same line as a real credential is one finding's
// value, not the line's. The other finding keeps its rating.
func TestPublishedExampleDoesNotLowerItsNeighbour(t *testing.T) {
	body := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE STRIPE_SKEY=sk_live_" + seededBody(15, alnum, 24) + "\n"
	got := byRule(t, scanAt(t, ".env", body))
	if f := got["SEC-001"]; f.Severity != findings.SeverityInfo {
		t.Errorf("SEC-001 severity = %q, want info", f.Severity)
	}
	f, ok := got["SEC-030"]
	if !ok {
		t.Fatal("SEC-030 reported nothing for the live key")
	}
	if f.Severity != findings.SeverityCritical || f.Metadata[findings.MetaValueClass] != "" {
		t.Errorf("SEC-030 = %s %q, want critical with no class", f.Severity, f.Metadata[findings.MetaValueClass])
	}
}
