package rules

import "testing"

// An OptIn rule does not run until the scan enables it by ID
// (scan.rules.enable); enabling an ID that names no OptIn rule changes nothing.
func TestAnOptInRuleRunsOnlyWhenEnabled(t *testing.T) {
	rs := NewRuleSet()
	rs.Add(&Rule{ID: "T-OPT", MatcherType: "regex", Pattern: `needle`, OptIn: true})
	rs.Add(&Rule{ID: "T-DEF", MatcherType: "regex", Pattern: `needle`})
	fired := func(e *Engine) map[string]bool {
		got, err := e.ScanFile("a.txt", []byte("a needle here\n"))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, f := range got {
			out[f.RuleID] = true
		}
		return out
	}

	off := NewEngine(rs)
	if got := fired(off); got["T-OPT"] || !got["T-DEF"] {
		t.Fatalf("not enabled: fired %v, want only T-DEF", got)
	}
	on := NewEngine(rs)
	on.EnableOptIn([]string{"T-OPT", "NO-SUCH-RULE"})
	if got := fired(on); !got["T-OPT"] || !got["T-DEF"] {
		t.Fatalf("enabled: fired %v, want both", got)
	}
}
