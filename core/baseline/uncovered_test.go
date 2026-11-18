package baseline

import (
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// Uncovered is the add side of the counting rule: it names, per occurrence, the
// findings the matcher would still report, so `baseline add` can accept them.
func TestUncovered(t *testing.T) {
	tests := []struct {
		name     string
		existing []Entry
		current  []findings.Finding
		wantLine []int
	}{
		{"two occurrences, no entry", nil,
			[]findings.Finding{finding("fp1", 8), finding("fp1", 11)}, []int{8, 11}},
		{"one entry present, two occurrences adds one",
			[]Entry{entry("fp1")},
			[]findings.Finding{finding("fp1", 8), finding("fp1", 11)}, []int{11}},
		{"fully covered adds nothing",
			[]Entry{entry("fp1"), entry("fp1")},
			[]findings.Finding{finding("fp1", 8), finding("fp1", 11)}, nil},
		{"spare entries add nothing",
			[]Entry{entry("fp1"), entry("fp1"), entry("fp1")},
			[]findings.Finding{finding("fp1", 8)}, nil},
		{"distinct fingerprints unaffected",
			[]Entry{entry("fp1")},
			[]findings.Finding{finding("fp1", 8), finding("fp2", 9)}, []int{9}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := loaded(tc.existing...).Uncovered(tc.current)
			var lines []int
			for _, i := range got {
				lines = append(lines, tc.current[i].Location.StartLine)
			}
			if len(lines) != len(tc.wantLine) {
				t.Fatalf("uncovered lines = %v, want %v", lines, tc.wantLine)
			}
			for i := range lines {
				if lines[i] != tc.wantLine[i] {
					t.Fatalf("uncovered lines = %v, want %v", lines, tc.wantLine)
				}
			}
		})
	}
}

func TestUncoveredAliasCountsAsCovered(t *testing.T) {
	f := finding("new", 8)
	f.AliasFingerprints = []string{"old"}
	if got := loaded(entry("old")).Uncovered([]findings.Finding{f}); len(got) != 0 {
		t.Fatalf("a finding accepted via its alias must not get a second entry, got %v", got)
	}
}

func TestCovered(t *testing.T) {
	b := loaded(entry("fp1"), entry("fp1"), entry("fp2"))
	if n := b.Covered("fp1"); n != 2 {
		t.Errorf("Covered(fp1) = %d, want 2", n)
	}
	if n := b.Covered("nope"); n != 0 {
		t.Errorf("Covered(nope) = %d, want 0", n)
	}
}
