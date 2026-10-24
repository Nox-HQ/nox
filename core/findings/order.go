package findings

import (
	"fmt"
	"sort"
	"strings"
)

// compareFindings is the one total order over findings. Every place that must
// choose between findings (sorting, and picking the survivor of a duplicate)
// uses it, so the choice depends on what the findings ARE and never on the
// order analyzers happened to hand them over in.
//
// The leading keys are the historical SortDeterministic order, so findings.json
// keeps its byte layout. After them come the fields that can differ between
// two findings the leading keys cannot tell apart: Deduplicate keys on
// fingerprint, line and column only, so two analyzers (or one analyzer twice)
// can produce findings that tie there and still disagree on severity, message
// or metadata. Which of them survived used to be whichever arrived first, and
// the analyzers finish in goroutine completion order.
func compareFindings(a, b *Finding) int {
	if c := strings.Compare(a.RuleID, b.RuleID); c != 0 {
		return c
	}
	if c := strings.Compare(a.Location.FilePath, b.Location.FilePath); c != 0 {
		return c
	}
	if c := cmpInt(a.Location.StartLine, b.Location.StartLine); c != 0 {
		return c
	}
	if c := strings.Compare(a.Fingerprint, b.Fingerprint); c != 0 {
		return c
	}
	if c := cmpInt(a.Location.StartColumn, b.Location.StartColumn); c != 0 {
		return c
	}
	if c := cmpInt(a.Location.EndLine, b.Location.EndLine); c != 0 {
		return c
	}
	if c := cmpInt(a.Location.EndColumn, b.Location.EndColumn); c != 0 {
		return c
	}
	return strings.Compare(contentKey(a), contentKey(b))
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// contentKey renders every field compareFindings has not yet compared, with
// metadata in key order (map iteration order must not leak into it). It is only
// built for findings that tie on location and fingerprint, which is rare, so
// the allocation is not on the hot path.
func contentKey(f *Finding) string {
	keys := make([]string, 0, len(f.Metadata))
	for k := range f.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "%d|%q|%q|%q|%q|%q|%q|%q|%q|%q", SeverityRank(f.Severity), f.Severity,
		f.Confidence, f.Message, f.ID, f.Status, f.Exploitability, f.EvidenceConfidence,
		f.CompetenceProfile, f.RetiredRuleIDs)
	fmt.Fprintf(&b, "|%q", f.AliasFingerprints)
	for _, k := range keys {
		fmt.Fprintf(&b, "|%q=%q", k, f.Metadata[k])
	}
	return b.String()
}

// IndexByFingerprint maps each fingerprint to the index of its representative
// in ff: the finding that sorts LAST under compareFindings.
//
// A v2 fingerprint is line-independent, so one fingerprint can name several
// findings (IAC-003 on every ADD line of a Dockerfile). A caller that needs
// ONE of them for a fingerprint took the last it saw, which is a property of
// the slice order and not of the findings; this takes the same one whatever
// order ff is in. Last, not first, so that a caller handed an already sorted
// slice (every scan result is) gets exactly the finding it always did.
func IndexByFingerprint(ff []Finding) map[string]int {
	idx := make(map[string]int, len(ff))
	for i := range ff {
		if cur, ok := idx[ff[i].Fingerprint]; !ok || compareFindings(&ff[i], &ff[cur]) > 0 {
			idx[ff[i].Fingerprint] = i
		}
	}
	return idx
}
