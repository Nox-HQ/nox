package findings

import (
	"testing"
)

// SortDeterministic must impose a total order, not merely a longer one.
//
// Dependency findings are the case that exposed this: every VULN-001 in one
// lockfile carries the same rule, the same path, and line 1. Sorting by
// rule/path/line alone leaves them all tied, so their order in findings.json
// came from the order the analyzer emitted them — Go map iteration, which is
// randomised. Same inputs, different output.
func TestSortDeterministic_TotalOrderOnTiedLocation(t *testing.T) {
	build := func(ids []string) *FindingSet {
		fs := NewFindingSet()
		for _, id := range ids {
			fs.Add(Finding{
				RuleID:   "VULN-001",
				Severity: SeverityMedium,
				Location: Location{FilePath: "package-lock.json", StartLine: 1},
				Message:  "Known vulnerability " + id,
			})
		}
		fs.SortDeterministic()
		return fs
	}

	forward := []string{"GHSA-aaa", "GHSA-bbb", "GHSA-ccc", "GHSA-ddd", "GHSA-eee"}
	reverse := []string{"GHSA-eee", "GHSA-ddd", "GHSA-ccc", "GHSA-bbb", "GHSA-aaa"}
	shuffled := []string{"GHSA-ccc", "GHSA-aaa", "GHSA-eee", "GHSA-bbb", "GHSA-ddd"}

	want := build(forward).Findings()
	for name, order := range map[string][]string{"reverse": reverse, "shuffled": shuffled} {
		got := build(order).Findings()
		if len(got) != len(want) {
			t.Fatalf("%s: got %d findings, want %d", name, len(got), len(want))
		}
		for i := range got {
			if got[i].Fingerprint != want[i].Fingerprint {
				t.Errorf("%s: position %d = %s, want %s — emission order changed the output",
					name, i, got[i].Fingerprint, want[i].Fingerprint)
			}
		}
	}
}

// The primary keys still win over the tiebreak: a finding earlier by rule,
// path, or line sorts first however its fingerprint compares.
func TestSortDeterministic_PrimaryKeysOutrankFingerprint(t *testing.T) {
	fs := NewFindingSet()
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "b.go", StartLine: 9}, Message: "z"})
	fs.Add(Finding{RuleID: "SEC-001", Location: Location{FilePath: "z.go", StartLine: 99}, Message: "a"})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "a.go", StartLine: 1}, Message: "y"})
	fs.Add(Finding{RuleID: "SEC-002", Location: Location{FilePath: "b.go", StartLine: 2}, Message: "x"})
	fs.SortDeterministic()

	type key struct {
		rule, path string
		line       int
	}
	want := []key{
		{"SEC-001", "z.go", 99},
		{"SEC-002", "a.go", 1},
		{"SEC-002", "b.go", 2},
		{"SEC-002", "b.go", 9},
	}
	got := fs.Findings()
	for i, w := range want {
		g := key{got[i].RuleID, got[i].Location.FilePath, got[i].Location.StartLine}
		if g != w {
			t.Errorf("position %d = %+v, want %+v", i, g, w)
		}
	}
}
