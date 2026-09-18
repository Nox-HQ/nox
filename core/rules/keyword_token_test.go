package rules

import "testing"

// A vendor keyword is the only evidence a bare-token rule has.
//
// It was matched as a plain substring, so the evidence could be manufactured by
// coincidence: SEC-533 is gated on "ibm" and produced 448 findings on the
// pinned corpus, many licensed by base64 in which `IBM` happens to appear --
// the Cloudflare cookie value `...Fszr_Msw0B1.IBMki` is one. `lob`, `fcm`,
// `wise`, `heap` and `split` are short enough to have the same problem, and
// once the keyword is satisfied every token nearby inherits the vendor's name.

func TestKeywordAsToken(t *testing.T) {
	for _, tc := range []struct {
		name, hay, kw string
		want          bool
	}{
		// The defect.
		{"ibm inside base64", "fszr_msw0b1.ibmki-1739", "ibm", false},
		{"lob inside a word", "the global embedding vector", "lob", false},
		{"fcm inside a run", "aaafcmbbb", "fcm", false},

		// What must keep working: separators are boundaries.
		{"snake case", "posthog_api_key = x", "posthog", true},
		{"kebab case", "ibm-cloud-key: x", "ibm", true},
		{"standalone", "using ibm here", "ibm", true},
		{"start of line", "ibm_key = 1", "ibm", true},
		{"end of line", "vendor is ibm", "ibm", true},
		{"dotted", "cloud.ibm.com", "ibm", true},

		// Prefix keywords sit directly against their value: no right boundary.
		{"underscore prefix", "ghp_abc123def", "ghp_", true},
		{"hyphen prefix", "key-1a2b3c4d", "key-", true},
		{"multi-part prefix", "sk-ant-api03-xyz", "sk-ant-api", true},

		// Punctuation keywords are unaffected (SEC-161 uses "=" and ":").
		{"equals", "const x = y", "=", true},
		{"colon", "api_key: value", ":", true},

		// Case folding still applies (caller lowercases both).
		{"absent", "nothing here", "ibm", false},
		{"empty keyword", "anything", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := keywordAsToken(tc.hay, tc.kw); got != tc.want {
				t.Errorf("keywordAsToken(%q, %q) = %v, want %v", tc.hay, tc.kw, got, tc.want)
			}
		})
	}
}

// TestASecondOccurrenceStillCounts. The first place a keyword appears may be
// embedded; a later one may be a real token, and scanning must not stop early.
func TestASecondOccurrenceStillCounts(t *testing.T) {
	if !keywordAsToken("xxibmxx and then ibm_key", "ibm") {
		t.Error("gave up after an embedded first occurrence; a real token later on the " +
			"line is still evidence")
	}
}

// TestExcludeKeywordsStaySubstrings pins the asymmetry. ExcludeContextKeywords
// veto a finding, and a veto that fires too readily suppresses -- the direction
// that cannot invent evidence. Only the positive gate is tightened.
func TestExcludeKeywordsStaySubstrings(t *testing.T) {
	lines := []string{"this is an examples fixture"}
	if !codeContextHasKeyword(lines, 1, 1, 4, []string{"example"}) {
		t.Error("an exclude keyword stopped matching as a substring; a defensive-context " +
			"veto is meant to be generous")
	}
	if contextHasKeyword(lines, 1, 1, 4, []string{"example"}) {
		t.Error("the POSITIVE gate matched `example` inside `examples`; that is the " +
			"substring evidence this change removes")
	}
}
