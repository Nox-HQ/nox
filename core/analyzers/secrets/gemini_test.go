package secrets

import (
	"slices"
	"testing"
)

// SEC-569 "Detected Gemini API Key" could not match a Gemini API key.
//
// A Gemini key IS a Google API key: `AIza` followed by 35 characters. SEC-569
// held `\b[a-zA-Z0-9]{24}\b` keyed on the word "gemini", which cannot match
// that (wrong length, and `AIza` is not in the class). What it matched instead
// was any 24-character run near the word -- and in Google API fixtures
// "gemini" is the MODEL NAME, so it sat beside every response id in the file.
// 1,097 findings on the pinned corpus, 78.9% of all remaining class-C volume.
//
// The coverage was never missing: SEC-007 already reports the real format. So
// SEC-569 is retired into it rather than redesigned, which would have made a
// fourth rule matching what SEC-007, SEC-415 and SEC-806 already match.

const realGeminiKey = "AIzaSyD-9tMv2kL3pQ7rX1nB5cW8eR4tY6uI0oP"

func scanLines(t *testing.T, body string) []string {
	t.Helper()
	a := NewAnalyzer()
	found, err := a.ScanFile("app.py", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(found))
	for _, f := range found {
		ids = append(ids, f.RuleID)
	}
	return ids
}

// TestARealGeminiKeyIsReported is the coverage that must survive the retirement.
func TestARealGeminiKeyIsReported(t *testing.T) {
	ids := scanLines(t, "# gemini configuration\nGEMINI_API_KEY = \""+realGeminiKey+"\"\n")
	if !slices.Contains(ids, "SEC-007") {
		t.Errorf("a real Gemini key is not reported by SEC-007; ids=%v. Retiring SEC-569 "+
			"into SEC-007 is only sound while SEC-007 reports the real format.", ids)
	}
}

// TestSEC569IsNotReportedAsALiveRule. The retirement has to actually remove it.
func TestSEC569IsNotReportedAsALiveRule(t *testing.T) {
	ids := scanLines(t, "# gemini configuration\nrequest_id = \"a1b2c3d4e5f6g7h8i9j0k1l2\"\n")
	if slices.Contains(ids, "SEC-569") {
		t.Error("SEC-569 still fires as a live rule on a 24-character request id")
	}
}

// TestSEC007CarriesTheRetiredIdentity. Baselines hash the rule ID, and VEX
// statements and nox:ignore comments name it directly, so a finding must answer
// to the ID it absorbed or every accepted SEC-569 silently un-waives.
func TestSEC007CarriesTheRetiredIdentity(t *testing.T) {
	a := NewAnalyzer()
	rule, ok := a.Rules().ByID("SEC-007")
	if !ok {
		t.Fatal("SEC-007 is gone; the rule SEC-569 was retired into no longer exists")
	}
	var absorbs bool
	for _, r := range rule.Retires {
		if r.ID == "SEC-569" {
			absorbs = true
			if r.Pattern == "" {
				t.Error("SEC-569 is absorbed with an empty frozen pattern, so its alias " +
					"fingerprint cannot be reproduced and baselines keyed on it break")
			}
		}
	}
	if !absorbs {
		t.Error("SEC-007 does not declare SEC-569 among its retired IDs")
	}
}
