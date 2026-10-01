package findings

import "testing"

// Fingerprints ignore the line position (v2), so two matches of the same text
// on one line share rule, path, line and fingerprint and differ only in
// column. The deterministic order must still decide between them, or the
// output order depends on the order the analyzers happened to produce them.
func TestSortDeterministicIsATotalOrder(t *testing.T) {
	mk := func(col int) Finding {
		return Finding{RuleID: "AI-039", Fingerprint: "same", Location: Location{FilePath: "f.opml", StartLine: 9, StartColumn: col, EndLine: 9, EndColumn: col + 13}}
	}
	order := func(in ...Finding) []int {
		fs := NewFindingSet()
		fs.items = append(fs.items, in...)
		fs.SortDeterministic()
		var cols []int
		for _, f := range fs.items {
			cols = append(cols, f.Location.StartColumn)
		}
		return cols
	}
	a := order(mk(116), mk(69))
	b := order(mk(69), mk(116))
	if a[0] != b[0] || a[1] != b[1] {
		t.Fatalf("input order decides the output: %v vs %v", a, b)
	}
	if a[0] != 69 {
		t.Errorf("ties on line are not ordered by column: %v", a)
	}
}
