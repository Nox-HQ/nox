package main

import (
	"fmt"
	"strings"
)

// renderRuleReview prints the three signals as three independent sections.
//
// Every section carries its own "what this is / what this is not" line,
// because each of these numbers has already been misread once in this
// repository. A finding count was read as a rule's badness when it was a
// documentation tree copied into four languages and two versions; a rule
// exercised in one place was read as a narrow rule when it was an
// under-covered one. The prose is the part that stops the table being wrong.
func renderRuleReview(report *RuleReviewReport) string {
	var b strings.Builder

	b.WriteString("# Rule review candidates\n\n")
	b.WriteString("Rule propositions worth a human read. Nothing here is a verdict:\n")
	b.WriteString("no rule is scored, ranked, suppressed, retired or changed by this\n")
	b.WriteString("report, and a rule appearing in several sections is a rule to\n")
	b.WriteString("inspect, not a rule that is several times as bad.\n\n")
	fmt.Fprintf(&b, "Catalogue: %d built-in rules.\n", report.Sources.Catalog)
	if report.Sources.Bench != "" {
		fmt.Fprintf(&b, "Bench:     %s\n", report.Sources.Bench)
	}
	if report.Sources.Sweep != "" {
		fmt.Fprintf(&b, "Sweep:     %s\n", report.Sources.Sweep)
	}
	b.WriteString("\n")

	renderContradictions(&b, report)
	renderCollapses(&b, report)
	renderSingleConstruct(&b, report)

	return b.String()
}

func renderContradictions(b *strings.Builder, report *RuleReviewReport) {
	b.WriteString("## Remediation contradicts trigger\n\n")
	b.WriteString("The rule pins a parameter to a literal value, and its own remediation\n")
	b.WriteString("recommends a range containing that value — so following the advice can\n")
	b.WriteString("leave the finding in place. Read as: this proposition did not survive\n")
	b.WriteString("being written down twice.\n\n")
	b.WriteString("NOT a bug report. A maintainer may well conclude the rule is right and\n")
	b.WriteString("the wording is loose, and rewording is the fix.\n\n")

	if len(report.Contradictions) == 0 {
		b.WriteString("None.\n\n")
		return
	}
	for _, c := range report.Contradictions {
		fmt.Fprintf(b, "- **%s** — flags `%s = %s`; remediation endorses %s for `%s` (range [%g, %g] contains %s)\n",
			c.Rule, c.Param, c.Flagged, "`"+c.Endorsement+"`", c.Param, c.EndorsedLow, c.EndorsedHi, c.Flagged)
		fmt.Fprintf(b, "  > %s\n", c.Remediation)
	}
	b.WriteString("\n")
}

func renderCollapses(b *strings.Builder, report *RuleReviewReport) {
	b.WriteString("## Prevalence collapses under authorship\n\n")
	b.WriteString("Raw findings exceed authored occurrences: the rule's apparent\n")
	b.WriteString("prevalence is partly the corpus copying one line, not the rule firing\n")
	b.WriteString("on many. Read the factor, not the rank — a rule at 1.01 has six\n")
	b.WriteString("duplicated lines and a rule at 13.0 is one page in thirteen copies.\n\n")
	b.WriteString("NOT evidence the rule is wrong. A correct rule fires as often as the\n")
	b.WriteString("corpus repeats the thing it detects.\n\n")

	if report.Sources.Bench == "" {
		b.WriteString("Not measured — pass `--bench <bench.json>`.\n\n")
		return
	}
	if len(report.Collapses) == 0 {
		b.WriteString("None: every rule's findings are distinct authored occurrences.\n\n")
		return
	}
	fmt.Fprintf(b, "| %-10s | %8s | %8s | %7s | %6s |\n", "rule", "findings", "authored", "factor", "repos")
	fmt.Fprintf(b, "|%s|%s|%s|%s|%s|\n", strings.Repeat("-", 12), strings.Repeat("-", 10),
		strings.Repeat("-", 10), strings.Repeat("-", 9), strings.Repeat("-", 8))
	for _, c := range report.Collapses {
		fmt.Fprintf(b, "| %-10s | %8d | %8d | %7.3f | %6d |\n",
			c.Rule, c.Findings, c.Authored, c.Factor, c.Repos)
	}
	b.WriteString("\n")
}

func renderSingleConstruct(b *strings.Builder, report *RuleReviewReport) {
	b.WriteString("## Exercised by a single construct\n\n")
	b.WriteString("Across the whole metamorphic corpus the rule fired on exactly one\n")
	b.WriteString("distinct construct, so the invariance check only ever tested it in one\n")
	b.WriteString("place. Read as: we cannot yet tell whether this rule is precise or\n")
	b.WriteString("merely overfit to the one example we have.\n\n")
	b.WriteString("NOT a defect. The remedy is usually a second construct in the corpus,\n")
	b.WriteString("not a change to the rule.\n\n")

	if report.Sources.Sweep == "" {
		b.WriteString("Not measured — pass `--sweep <triage.json>` from scripts/metamorphic/sweep.py.\n\n")
		return
	}
	if len(report.SingleConstruct) == 0 {
		b.WriteString("None.\n\n")
		return
	}
	for _, s := range report.SingleConstruct {
		fmt.Fprintf(b, "- **%s** — %d fires across %d seed(s): %s\n",
			s.Rule, s.FireCount, s.SeedCount, strings.Join(s.Seeds, ", "))
	}
	b.WriteString("\n")
}
