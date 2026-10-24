package taintflow

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/taint"
)

// A rule ID can be shared by sinks of more than one vulnerability class:
// TAINT-005 is reported for code_injection (CWE-94, CWE-95, CWE-134) and
// unsafe_deserialization (CWE-502) sinks, TAINT-003 for xss and ssti. One rule
// descriptor serves every finding with that ID, so it has to describe all of
// them. It used to describe whichever sink a map iteration reached first, so
// the SARIF catalog changed between identical scans and was wrong for the other
// class in every one of them.
func TestRulesDescribeEveryClassTheyReport(t *testing.T) {
	cat := taint.MustDefault()
	type pair struct{ class, cwe string }
	want := map[string]map[pair]bool{}
	for _, lang := range cat.Languages() {
		for _, s := range cat.Sinks(lang) {
			if want[s.RuleID] == nil {
				want[s.RuleID] = map[pair]bool{}
			}
			want[s.RuleID][pair{string(s.VulnClass), s.CWE}] = true
		}
	}

	shared := 0
	for _, r := range NewAnalyzer().Rules().Rules() {
		pairs := want[r.ID]
		if len(pairs) == 0 {
			t.Errorf("%s: rule has no sink in the catalog", r.ID)
			continue
		}
		classes := map[string]bool{}
		for p := range pairs {
			classes[p.class] = true
			if !strings.Contains(r.Description, p.cwe) {
				t.Errorf("%s: description %q omits %s, which its %s sinks report", r.ID, r.Description, p.cwe, p.class)
			}
			if !strings.Contains(r.Metadata["cwe"], p.cwe) {
				t.Errorf("%s: cwe metadata %q omits %s", r.ID, r.Metadata["cwe"], p.cwe)
			}
			if !strings.Contains(r.Description, p.class) {
				t.Errorf("%s: description %q omits class %s", r.ID, r.Description, p.class)
			}
		}
		if len(classes) > 1 {
			shared++
		}
	}
	// The premise of this test: if no ID were shared, the assertions above
	// would pass against the old first-seen construction too.
	if shared == 0 {
		t.Fatal("no rule ID is shared across vuln classes; this test no longer exercises anything")
	}
}

// The rule catalog must be the same bytes on every build. Map iteration order
// changes per range statement, so 64 builds in one process would expose a
// first-seen construction with near certainty; the sort order is asserted
// directly in core/taint.
func TestRulesAreDeterministic(t *testing.T) {
	a := NewAnalyzer()
	first := describeRules(t, a)
	for i := 0; i < 64; i++ {
		if got := describeRules(t, a); got != first {
			t.Fatalf("build %d of the taint rule catalog differs from the first", i+1)
		}
	}
}

// describeRules serializes the fields of each rule a report carries. A Rule
// itself holds compiled matchers, which do not marshal.
func describeRules(t *testing.T, a *Analyzer) string {
	t.Helper()
	var out []map[string]any
	for _, r := range a.Rules().Rules() {
		out = append(out, map[string]any{
			"id": r.ID, "description": r.Description, "severity": r.Severity, "remediation": r.Remediation,
			"tags": r.Tags, "references": r.References, "metadata": r.Metadata, "opt_in": r.OptIn,
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
