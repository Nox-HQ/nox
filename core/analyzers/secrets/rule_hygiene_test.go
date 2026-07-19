package secrets

import (
	"sort"
	"strings"
	"testing"
)

// TestNoFunctionallyIdenticalRules catches secret rules that are duplicates in
// every way that matters — same description, same pattern, same keyword set.
//
// Such a pair reports the SAME credential twice under two rule IDs, because
// findings are fingerprinted by rule ID: an operator triaging a real Heroku key
// saw "Heroku API Key" listed twice. Five such groups had accumulated. Merging
// their keyword sets and retiring the redundant IDs removes the double-report
// without losing any detection, and this test stops them recurring.
//
// Rules that share a description but differ in pattern are NOT flagged: a vendor
// can issue more than one credential format, and each format wants its own
// pattern.
func TestNoFunctionallyIdenticalRules(t *testing.T) {
	t.Parallel()

	type sig struct{ desc, pattern, keywords string }
	byID := map[string]sig{}
	groups := map[sig][]string{}

	for _, r := range builtinSecretRules() {
		kw := append([]string(nil), r.Keywords...)
		sort.Strings(kw)
		s := sig{r.Description, r.Pattern, strings.Join(kw, ",")}
		byID[r.ID] = s
		groups[s] = append(groups[s], r.ID)
	}

	for s, ids := range groups {
		if len(ids) > 1 {
			sort.Strings(ids)
			t.Errorf("rules %v are functionally identical (same description, pattern and keywords) "+
				"and will each report the same credential — merge them:\n    description: %q\n    pattern: %q\n    keywords: %q",
				ids, s.desc, s.pattern, s.keywords)
		}
	}
}

// TestSharedPatternRulesAreDistinguishable holds the stronger invariant that no
// two secret rules share a description AND a pattern at all.
//
// Two rules with the same description and pattern but different keywords still
// double-report on any file matching both keyword sets, and the identical
// description gives the operator no way to tell the two findings apart. A vendor
// that genuinely issues two credential formats should give each format its own
// pattern, which distinguishes them here.
func TestSharedPatternRulesAreDistinguishable(t *testing.T) {
	t.Parallel()

	type sig struct{ desc, pattern string }
	groups := map[sig][]string{}
	for _, r := range builtinSecretRules() {
		groups[sig{r.Description, r.Pattern}] = append(groups[sig{r.Description, r.Pattern}], r.ID)
	}

	const maxSharedGroups = 0 // every duplicate has been merged; a vendor with two formats needs two patterns
	shared := 0
	for s, ids := range groups {
		if len(ids) > 1 {
			shared++
			t.Logf("shared description+pattern: %v (%q)", ids, s.desc)
		}
	}
	if shared > maxSharedGroups {
		t.Errorf("%d groups share description+pattern, above the %d bound — a new duplicate crept in",
			shared, maxSharedGroups)
	}
}
