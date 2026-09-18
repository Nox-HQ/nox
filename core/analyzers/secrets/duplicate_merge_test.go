package secrets

import (
	"slices"
	"strings"
	"testing"
)

// Twelve groups of rules described one condition with two IDs, so one token
// produced two findings. Measured before the merge: a Shopify shared secret
// reported SEC-034 AND SEC-321, and a Shopify access token SEC-035 AND SEC-318.
//
// The Shopify, SendGrid, OpenSSH, PGP, Braintree, Mailchimp and Bittrex pairs
// were live duplicates -- their prefixes are not in dedup.go's canonicalOwners
// table, so nothing collapsed them at runtime. The `AIza` and `AKIA` groups
// were already collapsed there (SEC-007 sole owner; SEC-001 and SEC-508
// co-canonical), so retiring SEC-115, SEC-415 and SEC-411 makes the rule set
// say what the scanner already did.
//
// SEC-173 and SEC-174 are the pair worth naming: they claimed a Bittrex ACCESS
// key and a Bittrex SECRET key respectively, with one identical pattern, so
// both fired on whichever was present. A distinction that exists only in the
// description is not one the scanner makes.

func TestOneTokenProducesOneFinding(t *testing.T) {
	const hexes = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	for name, line := range map[string]string{
		"shopify shared secret": `SHOP = "shpss_` + hexes + `"`,
		"shopify access token":  `SHOP = "shpat_` + hexes + `"`,
		"shopify custom app":    `SHOP = "shpca_` + hexes + `"`,
		"shopify private app":   `SHOP = "shppa_` + hexes + `"`,
	} {
		ids := idsFor(t, "cfg.py", line+"\n")
		var shopify []string
		for _, id := range ids {
			if strings.HasPrefix(id, "SEC-03") || id == "SEC-318" || id == "SEC-319" ||
				id == "SEC-320" || id == "SEC-321" {
				shopify = append(shopify, id)
			}
		}
		if len(shopify) > 1 {
			t.Errorf("%s produced %d Shopify findings (%v); one token is one condition",
				name, len(shopify), shopify)
		}
	}
}

// TestRetiredIdentitiesSurviveTheMerge. Baselines hash the rule ID and VEX
// statements and nox:ignore comments name it, so a survivor must answer to what
// it absorbed or every accepted finding silently un-waives.
func TestRetiredIdentitiesSurviveTheMerge(t *testing.T) {
	a := NewAnalyzer()
	for survivor, absorbed := range map[string][]string{
		"SEC-034": {"SEC-321"},
		"SEC-035": {"SEC-318"},
		"SEC-036": {"SEC-319"},
		"SEC-037": {"SEC-320"},
		"SEC-391": {"SEC-428"},
		"SEC-392": {"SEC-429"},
		"SEC-038": {"SEC-142"},
		"SEC-059": {"SEC-378"},
		"SEC-153": {"SEC-376"},
		"SEC-508": {"SEC-411"},
		"SEC-173": {"SEC-174"},
		"SEC-007": {"SEC-569", "SEC-115", "SEC-415"},
	} {
		rule, ok := a.Rules().ByID(survivor)
		if !ok {
			t.Errorf("survivor %s is gone", survivor)
			continue
		}
		var got []string
		for _, r := range rule.Retires {
			got = append(got, r.ID)
			if r.Pattern == "" {
				t.Errorf("%s absorbs %s with an empty frozen pattern, so its alias "+
					"fingerprint cannot be reproduced", survivor, r.ID)
			}
		}
		for _, want := range absorbed {
			if !slices.Contains(got, want) {
				t.Errorf("%s does not declare %s among its retired IDs (has %v)",
					survivor, want, got)
			}
		}
	}
}

// TestMergedRulesAreGone. A merge that leaves the duplicate registered has
// achieved nothing.
func TestMergedRulesAreGone(t *testing.T) {
	a := NewAnalyzer()
	for _, id := range []string{
		"SEC-321", "SEC-318", "SEC-319", "SEC-320", "SEC-428", "SEC-429",
		"SEC-142", "SEC-378", "SEC-376", "SEC-115", "SEC-415", "SEC-411", "SEC-174",
	} {
		if _, ok := a.Rules().ByID(id); ok {
			t.Errorf("%s is still registered as a live rule", id)
		}
	}
}
