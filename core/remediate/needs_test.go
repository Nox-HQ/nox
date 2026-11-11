package remediate

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/assess"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fix"
)

const genericNeeds = "only you can choose"

// No rule may get the one-size sentence: every issue nox cannot fix says what
// it is missing and how to supply it.
func TestNeedsNeverGeneric(t *testing.T) {
	rs := BuiltinRules()
	for _, r := range catalog.Rules() {
		if hasContentFix(r.ID) || fix.ActionsPinRules[r.ID] {
			continue
		}
		n := needsFor(&assess.Issue{RuleID: r.ID}, rs)
		if _, own := needsByRule[r.ID]; !own {
			if _, ok := needsByFamily[catalog.Family(r.ID).Key]; !ok {
				t.Errorf("%s: family %q has no statement of what is missing", r.ID, catalog.Family(r.ID).Key)
			}
		}
		if strings.Contains(n, genericNeeds) || !strings.Contains(n, "To supply it") && needsByRule[r.ID] == "" {
			t.Errorf("%s: needs is generic or has no way to supply it: %q", r.ID, n)
		}
	}
}

// Different rules ask for different things, so their text differs.
func TestPerRuleNeedsAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for id, n := range needsByRule {
		if other, dup := seen[n]; dup {
			t.Errorf("%s and %s share one needs text: %q", id, other, n)
		}
		seen[n] = id
	}
	rs := BuiltinRules()
	a := needsFor(&assess.Issue{RuleID: "IAC-137"}, rs)
	b := needsFor(&assess.Issue{RuleID: "IAC-139"}, rs)
	if a == b {
		t.Fatal("resource limits and liveness probe must not ask for the same thing")
	}
}

func TestNoFixNeedsNameTheReason(t *testing.T) {
	cases := []struct {
		name string
		is   assess.Issue
		want string
	}{
		{"no fix published", assess.Issue{Ecosystem: "npm", Package: "left-pad", Version: "1.0.0"}, "none has been published"},
		{"unsupported ecosystem", assess.Issue{Ecosystem: "maven", Package: "org.example:lib", Version: "1.0.0", FixedIn: "1.0.5"}, "does not drive Maven"},
		{"not comparable", assess.Issue{Ecosystem: "npm", Package: "x", Version: "", FixedIn: "2.0.0"}, "could not establish"},
	}
	for _, c := range cases {
		it := Item{}
		is := c.is
		classifyNoFix(&it, &is)
		if !strings.Contains(it.Needs, c.want) {
			t.Errorf("%s: %q lacks %q", c.name, it.Needs, c.want)
		}
	}
}

// A rule in the secrets family that reports a resource identifier or a public
// key is not reporting a credential: nothing was exposed, so telling the reader
// to treat the value as compromised and rotate it sends them to do work that
// does not exist.
func TestNeedsDoesNotRotateWhatIsNotACredential(t *testing.T) {
	rs := BuiltinRules()
	checked := 0
	for _, r := range rs.Rules() {
		if catalog.Family(r.ID).Key != "secrets" || r.Severity != findings.SeverityInfo {
			continue
		}
		checked++
		id := r.ID
		n := needsFor(&assess.Issue{RuleID: id}, rs)
		for _, wrong := range []string{"compromised", "replacement secret", "rotate it at its provider"} {
			if strings.Contains(n, wrong) {
				t.Errorf("%s reports no credential, yet its needs say %q: %q", id, wrong, n)
			}
		}
		if !strings.Contains(n, "To supply it") {
			t.Errorf("%s: needs has no way to supply it: %q", id, n)
		}
	}
	if checked == 0 {
		t.Fatal("no info-severity secrets rule was checked; SEC-372 is one")
	}
	// A credential rule keeps the instruction.
	if n := needsFor(&assess.Issue{RuleID: "SEC-001"}, rs); !strings.Contains(n, "compromised") {
		t.Errorf("SEC-001 reports a credential; its needs must say to treat it as compromised: %q", n)
	}
}

// What follows "To supply it:" is guidance. A note about where a rule's
// pattern came from is not, and no rule may print one there.
func TestNeedsCarryGuidanceNotProvenance(t *testing.T) {
	rs := BuiltinRules()
	for _, r := range catalog.Rules() {
		n := needsFor(&assess.Issue{RuleID: r.ID}, rs)
		if strings.Contains(n, "Imported from") {
			t.Errorf("%s: needs print the rule's provenance as guidance: %q", r.ID, n)
		}
	}
}
