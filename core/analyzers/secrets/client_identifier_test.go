package secrets

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

const lowerAlnum = "abcdefghijklmnopqrstuvwxyz0123456789"

// uuidBody generates a UUID-shaped identifier at test time.
func uuidBody() string {
	h := tokenBody(32, "0123456789abcdef")
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// A client ID or account SID names an application or account. It is sent in the
// clear (an OAuth client ID is in every sign-in URL; a Twilio Account SID is the
// username half of basic auth) and authenticates nothing without the secret that
// pairs with it, which other rules report. These rules claimed CWE-798 at high
// severity and told the operator to rotate the value: on a real repository the
// fix plan led with "treat the exposed value as compromised" for a LinkedIn
// client ID and a Twilio SID in .env.example. They keep reporting the value, as
// what it is.
func TestAudit_ClientIdentifiersAreNotCredentials(t *testing.T) {
	cases := []struct{ id, file, src string }{
		{"SEC-260", "app.env", "linkedin_client_id = \"" + tokenBody(14, lowerAlnum) + "\"\n"},
		{"SEC-264", "app.env", "looker_client_id = \"" + tokenBody(20, lowerAlnum) + "\"\n"},
		{"SEC-274", "app.env", "messagebird_client_id = \"" + uuidBody() + "\"\n"},
		{"SEC-292", "app.env", "plaid_client_id = \"" + tokenBody(24, lowerAlnum) + "\"\n"},
		{"SEC-379", "notify.py", "# twilio_sid\nACCOUNT = \"AC" + tokenBody(32, lowerAlnum) + "\"\n"},
		{"SEC-421", "app.env", "azure_client_id = \"" + uuidBody() + "\"\n"},
		{"SEC-557", "app.env", "twilio_account_sid=AC" + tokenBody(32, "0123456789abcdef") + "\n"},
		{"SEC-559", "app.env", "plaid_client = \"" + tokenBody(32, lowerAlnum) + "\"\n"},
		{"SEC-756", "app.env", "google_oauth_client_id=" + tokenBody(12, "0123456789") + "-" + tokenBody(32, lowerAlnum) + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			f, ok := findingFor(scanOne(t, tc.file, tc.src), tc.id)
			if !ok {
				t.Fatalf("%s did not report the identifier it describes:\n%s", tc.id, tc.src)
			}
			if f.Severity != findings.SeverityInfo {
				t.Errorf("%s severity = %s; an identifier is not a credential and is informational", tc.id, f.Severity)
			}
			if f.Metadata["cwe"] == "CWE-798" {
				t.Errorf("%s still claims CWE-798 (hard-coded credentials) for an identifier", tc.id)
			}
			if !strings.Contains(f.Message, "not a credential") {
				t.Errorf("%s message does not say what it found: %q", tc.id, f.Message)
			}
			if strings.Contains(strings.ToLower(f.Message), "rotate") {
				t.Errorf("%s message tells the operator to rotate something that is not a secret: %q", tc.id, f.Message)
			}
		})
	}
}
