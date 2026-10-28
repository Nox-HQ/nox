package assess

import (
	"fmt"
	"io"
	"strings"
)

// DefaultLimit is how many issues the assessment lists before summarising the
// rest. Five is enough to act on today and short enough to read.
const DefaultLimit = 5

// RenderOptions control the text rendering.
type RenderOptions struct {
	// Limit caps the issues listed; 0 lists every one.
	Limit int
}

// Render writes the assessment as plain text. It reads nothing but r, so the
// same report always renders to the same bytes.
func Render(w io.Writer, r Report, opts RenderOptions) error {
	b := &strings.Builder{}
	b.WriteString("\nNox Security Assessment\n\n")
	renderIssues(b, r, opts.Limit)
	renderCoverage(b, r)
	if len(r.Undetermined) > 0 {
		b.WriteString("\nNot determined by this scan:\n")
		for _, u := range r.Undetermined {
			fmt.Fprintf(b, "  - %s\n", u)
		}
	}
	if len(r.Verify) > 0 || len(r.Leads) > 0 {
		b.WriteString("\nAdditional verification recommended:\n")
		for _, v := range r.Verify {
			fmt.Fprintf(b, "  - Runtime testing for %s: %s (%s), e.g. %s.\n",
				v.Where, plural(v.Hypotheses, "attack hypothesis", "attack hypotheses"),
				strings.Join(v.Scenarios, ", "), v.Objective)
		}
		renderLeads(b, r, opts.Limit)
	}
	if len(r.NextSteps) > 0 {
		b.WriteString("\nNext steps:\n")
		for _, s := range r.NextSteps {
			fmt.Fprintf(b, "  - %s\n", s)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// renderLeads lists the scan's leads, capped like the issues.
func renderLeads(b *strings.Builder, r Report, limit int) {
	shown := r.Leads
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
	}
	for _, l := range shown {
		fmt.Fprintf(b, "  - %s: %s (%s:%d) %s. %s\n",
			capitalize(l.Category), l.Route, l.FilePath, l.Line, l.Statement, l.Test)
	}
	if rest := len(r.Leads) - len(shown); rest > 0 {
		fmt.Fprintf(b, "  ...and %s; run with --verbose to list every one.\n",
			plural(rest, "more route to test", "more routes to test"))
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func renderIssues(b *strings.Builder, r Report, limit int) {
	if len(r.Issues) == 0 {
		b.WriteString("No issues found in what was checked.\n")
		return
	}
	attention := r.Issues[:r.AttentionIssues]
	observations := r.Issues[r.AttentionIssues:]
	renderAttention(b, r, attention, limit)
	if len(observations) == 0 {
		return
	}
	obsFindings := r.FindingCount - r.AttentionFindings
	label := plural(len(observations), "lower-priority observation", "lower-priority observations")
	if limit > 0 {
		fmt.Fprintf(b, "\nPlus %s (%s): low severity, or a check that is unsure of the finding. "+
			"Run with --verbose to list them; nothing is hidden from findings.json or results.sarif.\n",
			label, plural(obsFindings, "finding", "findings"))
		return
	}
	fmt.Fprintf(b, "\n%s (%s): low severity, or a check that is unsure of the finding.\n",
		capitalize(label), plural(obsFindings, "finding", "findings"))
	for i, is := range observations {
		fmt.Fprintf(b, "  %d. %s\n", len(attention)+i+1, is.Summary)
	}
}

func renderAttention(b *strings.Builder, r Report, attention []Issue, limit int) {
	if len(attention) == 0 {
		b.WriteString("No issues need attention.\n")
		return
	}
	verb := "need"
	if len(attention) == 1 {
		verb = "needs"
	}
	fmt.Fprintf(b, "%s %s attention (%s).\n",
		plural(len(attention), "issue", "issues"), verb, plural(r.AttentionFindings, "finding", "findings"))
	shown := attention
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
	}
	for i, is := range shown {
		fmt.Fprintf(b, "  %d. %s\n", i+1, is.Summary)
	}
	if rest := len(attention) - len(shown); rest > 0 {
		fmt.Fprintf(b, "  ...and %s; run with --verbose to list every issue.\n",
			plural(rest, "more issue", "more issues"))
	}
}

func renderCoverage(b *strings.Builder, r Report) {
	b.WriteString("\n")
	if len(r.Checked) > 0 {
		fmt.Fprintf(b, "Checks completed: %s.\n", joinWords(r.Checked))
	} else {
		b.WriteString("Checks completed: none.\n")
	}
	var failed, disabled []Limit
	for _, l := range r.NotChecked {
		if l.Blocking {
			failed = append(failed, l)
		} else {
			disabled = append(disabled, l)
		}
	}
	if len(failed) > 0 {
		b.WriteString("Checks that did not complete (results may be incomplete):\n")
		renderLimits(b, failed)
	}
	if len(disabled) > 0 {
		b.WriteString("Not checked:\n")
		renderLimits(b, disabled)
	}
}

func renderLimits(b *strings.Builder, ls []Limit) {
	for _, l := range ls {
		if l.Action == "" {
			fmt.Fprintf(b, "  - %s\n", l.Summary)
			continue
		}
		fmt.Fprintf(b, "  - %s To enable: %s.\n", l.Summary, l.Action)
	}
}

// joinWords renders a, b and c.
func joinWords(ss []string) string {
	switch len(ss) {
	case 0:
		return ""
	case 1:
		return ss[0]
	}
	return strings.Join(ss[:len(ss)-1], ", ") + " and " + ss[len(ss)-1]
}
