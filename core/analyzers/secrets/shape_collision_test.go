package secrets

import (
	"slices"
	"strings"
	"testing"
)

// Category C of docs/design/identical-pattern-audit.md: two rules for DIFFERENT
// vendors sharing one token shape. Here a duplicate is not noise but
// misattribution -- an operator is told to rotate a credential that does not
// exist while the one that does goes unnamed.
//
// dedup.go resolves a span's canonical owner from the token's provider PREFIX,
// so the prefixed collisions were already handled. A shape with NO prefix has
// nothing to resolve, and measured before this change:
//
//	a bare UUID near `heroku_api` and `coinbase`        -> Heroku AND Coinbase
//	a bare 64-char token near `linode_token`, `scaleway` -> Linode AND Scaleway
//
// Binding each rule to its own vendor's key name dissolves the collision at the
// source: the two rules no longer match the same text, so there is nothing for
// dedup to arbitrate.

func TestOneTokenIsNotTwoVendors(t *testing.T) {
	const uuid = "12345678-1234-1234-1234-123456789012"
	sixtyFour := strings.Repeat("aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV", 2)

	for name, tc := range map[string]struct {
		body  string
		rules []string
	}{
		"uuid near two vendors": {
			"# heroku_api and coinbase integration\nTOKEN = \"" + uuid + "\"\n",
			[]string{"SEC-402", "SEC-565"},
		},
		"64 chars near two vendors": {
			"# linode_token and scaleway config\nTOKEN = \"" + sixtyFour + "\"\n",
			[]string{"SEC-472", "SEC-527"},
		},
	} {
		ids := idsFor(t, "cfg.py", tc.body)
		var hit []string
		for _, r := range tc.rules {
			if slices.Contains(ids, r) {
				hit = append(hit, r)
			}
		}
		if len(hit) > 1 {
			t.Errorf("%s: one token reported as %v — at most one of those credentials "+
				"exists, and naming both tells an operator to rotate the wrong one", name, hit)
		}
	}
}

// TestBoundVendorRulesStillReportTheirOwn is the recall half.
func TestBoundVendorRulesStillReportTheirOwn(t *testing.T) {
	const uuid = "12345678-1234-1234-1234-123456789012"
	sixtyFour := strings.Repeat("aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV", 2)
	for _, tc := range []struct{ rule, line string }{
		{"SEC-402", `heroku_api_key = "` + uuid + `"`},
		{"SEC-565", `coinbase_api_key = "` + uuid + `"`},
		{"SEC-472", `linode_token = "` + sixtyFour + `"`},
		{"SEC-527", `scaleway_api_token = "` + sixtyFour + `"`},
		{"SEC-399", `bugsnag_api_key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"`},
		{"SEC-568", `bitfinex_api_key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"`},
		{"SEC-482", `webflow_api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"`},
		{"SEC-530", `huawei_access_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2"`},
		{"SEC-614", `onesignal_api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2"`},
		{"SEC-658", `launchdarkly_api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0"`}, // 24 chars
	} {
		if got := idsFor(t, "cfg.py", tc.line+"\n"); !slices.Contains(got, tc.rule) {
			t.Errorf("%s no longer reports its own bound credential: %s\n   ids=%v",
				tc.rule, tc.line, got)
		}
	}
}

// TestSquarePosDoesNotClaimSquarespace. SEC-575 is bound to `square_pos`, not
// `square`, because "squarespace" contains "square" — the substring problem
// that has produced a wrong answer at every level of this workstream,
// including in the tooling written to fix it.
func TestSquarePosDoesNotClaimSquarespace(t *testing.T) {
	ids := idsFor(t, "cfg.py", `squarespace_api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0"`+"\n")
	if slices.Contains(ids, "SEC-575") {
		t.Error("SEC-575 (Square POS) claimed a Squarespace credential")
	}
}
