package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
)

// familyOf maps a rule ID to a human-readable family label. Operators
// see family labels rather than 11 distinct rule-ID prefixes; the
// prefixes themselves stay stable for tooling that joins on RuleID.
func familyOf(ruleID string) string { return catalog.Family(ruleID).Label }

// familySummary returns a one-line "Secrets:23, Infrastructure:12, ..." // nox:ignore SEC-163 -- code comment
// breakdown of active findings sorted by descending count. Returns "" on
// empty input.
func familySummary(items []findings.Finding) string {
	if len(items) == 0 {
		return ""
	}
	counts := map[string]int{}
	for i := range items {
		counts[familyOf(items[i].RuleID)]++
	}

	type kv struct {
		family string
		count  int
	}
	pairs := make([]kv, 0, len(counts))
	for f, c := range counts {
		pairs = append(pairs, kv{f, c})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].family < pairs[j].family
	})

	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%s:%d", p.family, p.count))
	}
	return strings.Join(parts, ", ")
}

// stagedFindingsLimit bounds the list a failed staged scan prints, so a commit
// that stages a vendored tree is answered with a screen and not a scrollback.
const stagedFindingsLimit = 10

// printStagedFindings names the findings that failed a staged scan: severity,
// rule, location and the rule's message, never the matched text. Most severe
// first, then by location, so the same index prints the same list.
func printStagedFindings(w io.Writer, gating []findings.Finding, verbose bool) {
	if len(gating) == 0 {
		return
	}
	items := append([]findings.Finding(nil), gating...)
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Severity != b.Severity {
			// "a meets threshold b" is "a is at least as severe as b".
			return nox.SeverityMeetsThreshold(a.Severity, b.Severity)
		}
		if a.Location.FilePath != b.Location.FilePath {
			return a.Location.FilePath < b.Location.FilePath
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.RuleID < b.RuleID
	})
	noun := "findings"
	if len(items) == 1 {
		noun = "finding"
	}
	_, _ = fmt.Fprintf(w, "[staged] %d %s in staged files:\n", len(items), noun)
	shown := items
	if !verbose && len(shown) > stagedFindingsLimit {
		shown = shown[:stagedFindingsLimit]
	}
	for i := range shown {
		f := &shown[i]
		_, _ = fmt.Fprintf(w, "  %-8s %s  %s:%d  %s\n", f.Severity, f.RuleID, f.Location.FilePath, f.Location.StartLine, f.Message)
	}
	if rest := len(items) - len(shown); rest > 0 {
		_, _ = fmt.Fprintf(w, "  and %d more: --verbose lists them all\n", rest)
	}
}
