package secrets

import (
	"strings"
	"testing"
)

// SEC-562 and SEC-572 shared the pattern `live_[a-zA-Z0-9]{32}` under two
// vendor names, so a single token near either word produced a finding named
// for the other. Neither vendor issues a credential beginning `live_`:
//
//   - Checkout.com secret keys are `sk_` (production) and `sk_sbox_` (sandbox),
//     the tail a lowercase base32-style run.
//   - Payoneer authenticates with OAuth2 client_id/client_secret and publishes
//     no token prefix, length or charset at all.
//
// So SEC-562 was redesigned onto the real prefixes and SEC-572 was removed —
// there is no format to encode.

func secretsFired(t *testing.T, rule, body string) bool {
	t.Helper()
	a := NewAnalyzer()
	got, err := a.ScanFile("config.py", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

// TestSEC562MatchesCheckoutsRealFormat uses the shape Checkout.com documents.
// The literals below are structurally valid and cryptographically worthless —
// a fixed character run, not a key anyone issued.
func TestSEC562MatchesCheckoutsRealFormat(t *testing.T) {
	for _, line := range []string{
		`secret = "sk_sbox_` + strings.Repeat("a1b2", 7) + `"`,
		`SECRET_KEY = "sk_` + strings.Repeat("c3d4", 7) + `"`,
	} {
		if !secretsFired(t, "SEC-562", line+"\n") {
			t.Errorf("SEC-562 missed a Checkout.com-shaped secret key: %s", line)
		}
	}
}

// TestSEC562DoesNotClaimStripesNamespace is the falsification of the comment on
// the rule. `sk_live_` and `sk_test_` belong to Stripe (SEC-030); the claim is
// that `[a-z0-9]{26,}` cannot cross the underscore, so the namespaces cannot
// overlap. If that reasoning is wrong these fire and two vendors collide again
// — which is the defect this change exists to remove.
func TestSEC562DoesNotClaimStripesNamespace(t *testing.T) {
	for _, line := range []string{
		`stripe.api_key = "sk_live_` + strings.Repeat("e5f6", 7) + `"`,
		`stripe.api_key = "sk_test_` + strings.Repeat("a7b8", 7) + `"`,
	} {
		if secretsFired(t, "SEC-562", line+"\n") {
			t.Errorf("SEC-562 claimed a Stripe key: %s — the `sk_live_`/`sk_test_` "+
				"namespace is SEC-030's, and the underscore is what was supposed to "+
				"keep them apart", line)
		}
	}
}

// TestSEC562IgnoresThePublishableKey. Checkout.com documents pk_ for
// client-side use. Reporting a credential the vendor publishes on purpose
// trains people to ignore the rule — the lesson from PostHog's phc_ (SEC-661).
func TestSEC562IgnoresThePublishableKey(t *testing.T) {
	line := `const publicKey = "pk_sbox_` + strings.Repeat("f9a0", 7) + `"`
	if secretsFired(t, "SEC-562", line+"\n") {
		t.Errorf("SEC-562 reported the publishable pk_ key: %s", line)
	}
}

// TestSEC572IsGone. Payoneer publishes no credential format, so there is
// nothing for a Payoneer-named rule to assert. A hardcoded OAuth client secret
// is still reported by the generic credential rules, which is the correct
// strength of claim.
func TestSEC572IsGone(t *testing.T) {
	for _, r := range builtinSecretRules() {
		if r.ID == "SEC-572" {
			t.Fatal("SEC-572 is back. Payoneer authenticates with OAuth2 " +
				"client_id/client_secret and documents no token prefix, length or " +
				"charset; any pattern given to this rule is invented. See the comment " +
				"where it used to be.")
		}
	}
}
