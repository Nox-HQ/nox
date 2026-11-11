package assess

import (
	"math"
	"sort"

	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
)

// valueOwners says, for each finding, which finding stands for it in an issue:
// itself, or the strongest credential finding whose match overlaps its own.
//
// The secrets analyzer keeps two findings on one value when two rules of equal
// standing both claim it (an AWS key is SEC-001 and SEC-508, a Lob key SEC-070
// and SEC-262). Those are two findings and one thing to do: the key is rotated
// once. Grouping by rule alone made them two issues with the same location.
//
// Ownership goes to the strongest overlapping finding, not to everything a
// chain of overlaps connects: a wide match over a line that holds two keys
// joins one of them, and the two keys stay two issues.
func valueOwners(ff []findings.Finding, used []bool) []int {
	owner := make([]int, len(ff))
	byFile := map[string][]int{}
	for i := range ff {
		owner[i] = i
		if !used[i] && reportsCredential(&ff[i]) {
			byFile[ff[i].Location.FilePath] = append(byFile[ff[i].Location.FilePath], i)
		}
	}
	for _, idx := range byFile {
		sort.SliceStable(idx, func(a, b int) bool { return startsBefore(&ff[idx[a]], &ff[idx[b]]) })
		for a, i := range idx {
			for _, j := range idx[a+1:] {
				if !startsBeforeEndOf(&ff[j], &ff[i]) {
					break // sorted by start: nothing later overlaps i either
				}
				if ff[i].Metadata[findings.MetaValueClass] != ff[j].Metadata[findings.MetaValueClass] {
					continue // the analyzer told the two values apart
				}
				if stronger(ff, j, owner[i]) {
					owner[i] = j
				}
				if stronger(ff, i, owner[j]) {
					owner[j] = i
				}
			}
		}
	}
	// A finding's owner may itself be owned by something stronger. Each step
	// moves to a strictly stronger finding, so the walk ends.
	for i := range owner {
		for owner[owner[i]] != owner[i] {
			owner[i] = owner[owner[i]]
		}
	}
	return owner
}

// reportsCredential is true for a finding a credential rule made: a rule in the
// secrets family above info severity. The info rules there report resource
// identifiers and public keys, which share a line with a credential without
// being one. A finding the analyzer reclassified by value is still a credential
// rule's, whatever severity it now carries, and two rules on one such value are
// one issue like any other.
func reportsCredential(f *findings.Finding) bool {
	if catalog.Family(f.RuleID).Key != "secrets" {
		return false
	}
	if f.Metadata[findings.MetaValueClass] != "" {
		return true
	}
	return f.Severity != findings.SeverityInfo && f.Severity != ""
}

// stronger orders two findings by rating, then by rule ID, then by scan order,
// so the same findings always elect the same owner.
func stronger(ff []findings.Finding, a, b int) bool {
	ra, rb := rank(ff[a].Severity, ff[a].Confidence), rank(ff[b].Severity, ff[b].Confidence)
	if ra != rb {
		return ra > rb
	}
	if ff[a].RuleID != ff[b].RuleID {
		return ff[a].RuleID < ff[b].RuleID
	}
	return a < b
}

func startsBefore(a, b *findings.Finding) bool {
	if a.Location.StartLine != b.Location.StartLine {
		return a.Location.StartLine < b.Location.StartLine
	}
	return a.Location.StartColumn < b.Location.StartColumn
}

// startsBeforeEndOf reports whether a begins before b ends. A finding with no
// end column is taken to run to the end of its last line.
func startsBeforeEndOf(a, b *findings.Finding) bool {
	end := b.Location.Normalized()
	endColumn := end.EndColumn
	if endColumn <= 0 {
		endColumn = math.MaxInt
	}
	if a.Location.StartLine != end.EndLine {
		return a.Location.StartLine < end.EndLine
	}
	return a.Location.StartColumn < endColumn
}

// alsoRules lists the other rules a group's findings come from, in order.
func alsoRules(group []findings.Finding, rule string) []string {
	seen := map[string]bool{rule: true}
	var out []string
	for i := range group {
		if id := group[i].RuleID; !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
