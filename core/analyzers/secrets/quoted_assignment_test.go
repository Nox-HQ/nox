package secrets

import (
	"slices"
	"testing"
)

// An assignment-bound rule that cannot match a QUOTED value misses the normal
// way the value is written.
//
// SEC-002, SEC-012 and SEC-014 matched `<name>\s*[=:]\s*` followed directly by
// the value class, with no provision for the quote that Python, JavaScript,
// JSON, YAML and TOML all put there. Measured directly: an AWS secret access
// key written `aws_secret_access_key = "kP9m..."` was reported only by SEC-510,
// a bare-token rule keyed on the word `aws_secret`, while SEC-002 -- the rule
// named for exactly this credential -- saw nothing. The unquoted spelling fired
// SEC-002 correctly.
//
// This matters beyond the three rules: the bare-token vendor rules were the
// only cover for the quoted form, so retiring them as duplicates BEFORE fixing
// this would have turned a precision problem into a false negative on a
// flagship credential.

func idsFor(t *testing.T, path, body string) []string {
	t.Helper()
	a := NewAnalyzer()
	found, err := a.ScanFile(path, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.RuleID)
	}
	return out
}

func TestQuotedAssignmentsAreMatched(t *testing.T) {
	const awsKey = "kP9mXq2LvR7tNc4WzB8yH3jF6dA1sE5gT0uI2oQx"
	const ibmKey = "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5Ab6Cd"
	const herokuKey = "12345678-1234-1234-1234-123456789012"

	for _, tc := range []struct {
		rule, line string
	}{
		{"SEC-002", `aws_secret_access_key = "` + awsKey + `"`},
		{"SEC-002", `aws_secret_access_key: '` + awsKey + `'`},
		{"SEC-014", `ibm_cloud_api_key = "` + ibmKey + `"`},
		{"SEC-012", `heroku_api_key = "` + herokuKey + `"`},
	} {
		got := idsFor(t, "config.py", tc.line+"\n")
		if !slices.Contains(got, tc.rule) {
			t.Errorf("%s did not report its own credential when quoted: %s\n   ids=%v",
				tc.rule, tc.line, got)
		}
	}
}

// TestUnquotedAssignmentsStillMatch guards the form that already worked.
func TestUnquotedAssignmentsStillMatch(t *testing.T) {
	for _, tc := range []struct {
		rule, line string
	}{
		{"SEC-002", `aws_secret_access_key = kP9mXq2LvR7tNc4WzB8yH3jF6dA1sE5gT0uI2oQx`},
		{"SEC-014", `ibm_cloud_api_key = Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5Ab6Cd`},
	} {
		if got := idsFor(t, "config.env", tc.line+"\n"); !slices.Contains(got, tc.rule) {
			t.Errorf("%s stopped reporting the unquoted form: %s\n   ids=%v", tc.rule, tc.line, got)
		}
	}
}
