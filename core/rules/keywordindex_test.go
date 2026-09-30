package rules

import (
	"bytes"
	"testing"
)

// The index must say "present" exactly when bytes.Contains does, for every
// keyword, or a rule would be skipped on a file it matches. Checked here for
// the edge shapes; TestKeywordIndexMatchesContainsOnFixtures checks the
// built-in rules' keywords over every fixture.
func TestKeywordIndexMatchesContains(t *testing.T) {
	rules := []*Rule{
		{ID: "A", Keywords: []string{"Stripe", "sk_live"}},
		{ID: "B", Keywords: []string{"-", "ab"}},     // under three bytes
		{ID: "C", Keywords: []string{"abc", "abcd"}}, // shared first trigram
		{ID: "D", Keywords: []string{"stripe"}},      // same keyword, another rule
		{ID: "E"},
		{ID: "F", Keywords: []string{""}}, // empty: Contains says always
	}
	x := newKeywordIndex(rules)
	for _, content := range []string{"", "a", "ab", "abc", "xxabcd", "STRIPE_KEY", "sk_live-", "stripsk_liv", "zzabzz"} {
		lower := bytes.ToLower([]byte(content))
		present := x.present(lower)
		for i, r := range rules {
			want := false
			for _, k := range r.Keywords {
				want = want || bytes.Contains(lower, bytes.ToLower([]byte(k)))
			}
			if got := x.anyPresent(present, i); got != want {
				t.Errorf("%q, rule %s: index %v, Contains %v", content, r.ID, got, want)
			}
		}
	}
}
