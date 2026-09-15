package secrets

import "testing"

// SEC-661 was named "Detected PostHog API Key" and could not match a PostHog
// API key.
//
// Its pattern was `\b[a-zA-Z0-9]{32}\b` keyed on the word "posthog". Every
// PostHog key is prefixed and longer than 32 characters, so no key is a bare
// 32-character run and none could match. What did match was any 32-character
// token near the word: 22,543 findings on the 2026-Q2 benchmark, none a
// PostHog key.
//
// PostHog's documented key types -- only one of the five is publishable:
//
//	phc_  project API key     PUBLIC, write-only, safe in client code
//	phx_  personal API key    secret; GitHub secret scanning rolls it
//	phs_  project secret key  secret
//	pha_  OAuth access token  secret
//	phr_  OAuth refresh token secret

func sec661Fires(t *testing.T, line string) bool {
	t.Helper()
	a := NewAnalyzer()
	found, err := a.engine.ScanFile("config.py", []byte("# posthog configuration\n"+line+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if f.RuleID == "SEC-661" {
			return true
		}
	}
	return false
}

// TestSEC661ReportsPostHogSecretKeys is the recall the rule never had.
func TestSEC661ReportsPostHogSecretKeys(t *testing.T) {
	for name, key := range map[string]string{
		"personal API key":   "phx_kL9mR3pZqW7nL2vB8sT4yH6jF0dA5cE1xY2zQ4wV6bN",
		"project secret key": "phs_9zQ4wV6bNkL9mR3pZqW7nL2vB8sT4yH6jF0dA5cE1xY",
		"OAuth access token": "pha_2vB8sT4yH6jF0dA5cE1xY9zQ4wV6bNkL9mR3pZqW7nL",
		"OAuth refresh":      "phr_6jF0dA5cE1xY9zQ4wV6bNkL9mR3pZqW7nL2vB8sT4yH",
	} {
		if !sec661Fires(t, `POSTHOG_KEY = "`+key+`"`) {
			t.Errorf("SEC-661 does not report a PostHog %s. The rule is named for "+
				"PostHog and cannot see PostHog's secret formats.", name)
		}
	}
}

// TestSEC661DoesNotReportThePublicProjectKey. PostHog documents phc_ as
// write-only and safe to ship in client-side code. Reporting a key the vendor
// tells people to publish trains them to ignore the rule.
func TestSEC661DoesNotReportThePublicProjectKey(t *testing.T) {
	const projectKey = "phc_PHQDA5KwztijnSojsxJ2c1DuJd52QCzJzT2xnSGvjN2"
	if sec661Fires(t, `POSTHOG_PROJECT_KEY = "`+projectKey+`"`) {
		t.Error("SEC-661 reports the phc_ project API key, which PostHog documents as " +
			"public and write-only")
	}
}

// TestSEC661DoesNotReportAnUnrelatedToken is the defect that produced the
// volume: a vendor-named rule firing on any token near the vendor's name.
func TestSEC661DoesNotReportAnUnrelatedToken(t *testing.T) {
	for _, line := range []string{
		`unrelated = "abcdefghijklmnopqrstuvwxyz012345"`,
		`session = "aQ4wE7rT9yU2iO5pA8sD1fG3hJ6kL0zX"`,
		`digest  = "d41d8cd98f00b204e9800998ecf8427e"`,
	} {
		if sec661Fires(t, line) {
			t.Errorf("SEC-661 fires on %q -- a 32-character token near the word "+
				"posthog is not evidence of a PostHog credential", line)
		}
	}
}
