package advisory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/report"
)

// The renderings below are shared by `nox advisories` and the MCP advisories
// tool, so the two cannot tell different stories about one decision. They are
// pure: they read the Result and nothing else.

// IncompleteReason names the checks that did not finish, or "".
//
// A degradation is advisory when it reports capability the operator did not ask
// for. Every other one is something the scan relies on that did not run, and a
// lookup that did not run is the one case where "no new advisories" is not a
// finding but an absence.
func IncompleteReason(ds []report.Degradation) string {
	var parts []string
	for _, d := range ds {
		if d.Advisory {
			continue
		}
		parts = append(parts, d.Kind+": "+d.Detail)
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// Headline is the one sentence that says what the run found, and says so
// plainly when it could not look (an incomplete scan, no previous run).
func Headline(res Result) string {
	newN, knownN, waivedN := res.Counts()
	switch {
	case res.Incomplete != "":
		return fmt.Sprintf("Scan incomplete: %s. Nothing was acted on, and this is not a clean result.", res.Incomplete)
	case !res.PreviousRun:
		return fmt.Sprintf("No previous run to compare against: %d advisories reported, none acted on. This run becomes the baseline for the next.", len(res.Decisions))
	case newN == 0:
		return fmt.Sprintf("No new advisories (%d known, %d waived).", knownN, waivedN)
	}
	return fmt.Sprintf("%d new advisories (%d known, %d waived). Policy %s, action %s.", newN, knownN, waivedN, res.Policy, res.Action)
}

// Text is the plain-text rendering of a decision, as `nox advisories` prints it.
func Text(res Result) string {
	var b strings.Builder
	b.WriteString(Headline(res))
	b.WriteString("\n")
	for i := range res.Decisions {
		d := res.Decisions[i]
		if d.Action == ActionNone {
			continue
		}
		fmt.Fprintf(&b, "\n  [%s] %s  %s %s@%s  severity=%s relevance=%s\n    %s\n",
			d.Action, d.Advisory, d.Ecosystem, d.Package, d.Version, d.Severity, d.Relevance.Label(), d.Reason)
	}
	if len(res.Prepare) > 0 {
		fmt.Fprintf(&b, "\nPull request: %d advisories. Auto-merge permitted: %t.\n", len(res.Prepare), res.AutoMerge)
	}
	return b.String()
}

// Markdown is the issue/job-summary rendering of a decision.
func Markdown(res Result) string {
	var b strings.Builder
	b.WriteString("## Nox advisory check\n\n")
	b.WriteString(Headline(res))
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "Policy `%s`, decision `%s`, auto-merge permitted `%t`.\n\n", res.Policy, res.Action, res.AutoMerge)
	var rows []Decision
	for i := range res.Decisions {
		if res.Decisions[i].Action != ActionNone {
			rows = append(rows, res.Decisions[i])
		}
	}
	if len(rows) == 0 {
		return b.String()
	}
	b.WriteString("| Advisory | Package | Severity | Relevance | Action |\n|---|---|---|---|---|\n")
	for _, d := range rows {
		fmt.Fprintf(&b, "| %s | %s %s@%s | %s | %s | %s |\n",
			d.Advisory, d.Ecosystem, d.Package, d.Version, d.Severity, d.Relevance.Label(), d.Action)
	}
	b.WriteString("\nWhy:\n\n")
	for _, d := range rows {
		fmt.Fprintf(&b, "- **%s** (%s): %s\n", d.Advisory, d.Action, d.Reason)
	}
	return b.String()
}
