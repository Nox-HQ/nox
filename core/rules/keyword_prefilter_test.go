package rules

import "testing"

// The keyword pre-filter runs for every rule against every scanned file. It
// used to rebuild `[]byte(strings.ToLower(kw))` on each of those calls — a
// constant, re-derived roughly 1,100 times per file for the secret rules
// alone, and 10% of scan CPU measured on anthropic-sdk-python.
//
// RuleSet.Add now lowers them once. These tests hold that in place, and hold
// the behaviour identical for a Rule that never went through Add.

// TestAddCachesLoweredKeywords is the optimisation itself.
func TestAddCachesLoweredKeywords(t *testing.T) {
	rs := NewRuleSet()
	r := &Rule{ID: "T-1", Keywords: []string{"Stripe", "SK_LIVE"}}
	rs.Add(r)
	if len(r.keywordsLower) != 2 {
		t.Fatalf("Add cached %d lowered keywords, want 2; the pre-filter is "+
			"re-lowering constants on every file again", len(r.keywordsLower))
	}
	for i, want := range []string{"stripe", "sk_live"} {
		if string(r.keywordsLower[i]) != want {
			t.Errorf("cached keyword %d = %q, want %q", i, r.keywordsLower[i], want)
		}
	}
}

// TestPrefilterIsCaseInsensitiveBothWays. The cache is only safe if it
// preserves the old behaviour exactly: content is lowered by the caller, the
// keyword by the cache, and an upper-case keyword must still match lower-case
// content and vice versa.
func TestPrefilterIsCaseInsensitiveBothWays(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keyword string
		content string
		want    bool
	}{
		{"upper keyword, lower content", "STRIPE", "stripe_key = 1", true},
		{"lower keyword, lower content", "stripe", "stripe_key = 1", true},
		{"mixed keyword", "StRiPe", "stripe_key = 1", true},
		{"absent", "twilio", "stripe_key = 1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := containsAnyKeyword([]byte(tc.content), loweredKeywords([]string{tc.keyword}))
			if got != tc.want {
				t.Errorf("containsAnyKeyword(%q, %q) = %v, want %v",
					tc.content, tc.keyword, got, tc.want)
			}
		})
	}
}

// TestARuleBuiltOutsideAddStillFilters. Tests and callers construct Rules
// directly. If such a rule silently lost its pre-filter it would still produce
// the right findings, just slower — the kind of regression nothing reports.
func TestARuleBuiltOutsideAddStillFilters(t *testing.T) {
	e := NewEngine(NewRuleSet())
	direct := &Rule{
		ID: "T-2", MatcherType: "regex", Pattern: `secret-[a-z]+`,
		Keywords: []string{"STRIPE"}, Severity: "high",
	}
	e.rules.rules = append(e.rules.rules, direct) // bypass Add on purpose
	if direct.keywordsLower != nil {
		t.Fatal("fixture invalid: this rule was supposed to bypass Add")
	}
	got, err := e.ScanFile("a.txt", []byte("stripe secret-abc\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("a rule that bypassed Add produced %d findings, want 1; the "+
			"fallback path in ScanFile no longer lowers keywords on the fly", len(got))
	}
	none, err := e.ScanFile("b.txt", []byte("secret-abc with no vendor word\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Errorf("the keyword gate did not apply to a rule built outside Add: %d findings", len(none))
	}
}
