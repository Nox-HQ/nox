package remediate

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// RenderPlan writes the plan as plain text. It reads nothing but the plan, so
// the same plan always renders to the same bytes, on every surface.
func RenderPlan(w io.Writer, p Plan) error {
	b := &strings.Builder{}
	b.WriteString("\nNox Fix Plan\n\n")
	if len(p.Items) == 0 {
		b.WriteString("Nothing to fix: the findings list holds no issues.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	fmt.Fprintf(b, "%s in %s: %d can be applied as they are, %d need your review, and %d need%s something nox does not have.\n",
		count(len(p.Items), "issue", "issues"), count(p.FindingCount, "finding", "findings"),
		p.Safe, p.Review, p.Info, map[bool]string{true: "s", false: ""}[p.Info == 1])
	section(b, p, ClassSafe, "Safe to apply", "Nothing here needs a decision from you.")
	section(b, p, ClassReview, "Needs your review", "Nox can prepare these, but a person should look first.")
	section(b, p, ClassInfo, "Needs information, or cannot be fixed automatically", "Nox will not guess at these.")
	b.WriteString("\nNext steps:\n")
	for _, s := range planNextSteps(p) {
		fmt.Fprintf(b, "  - %s\n", s)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func section(b *strings.Builder, p Plan, class Class, heading, lead string) {
	var items []*Item
	for i := range p.Items {
		if p.Items[i].Class == class {
			items = append(items, &p.Items[i])
		}
	}
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s (%d). %s\n", heading, len(items), lead)
	for _, it := range items {
		fmt.Fprintf(b, "  %d. %s\n", it.N, it.Title)
		writeDetail(b, it)
	}
}

func writeDetail(b *strings.Builder, it *Item) {
	if it.Why != "" {
		fmt.Fprintf(b, "     Why: %s\n", it.Why)
	}
	if it.Needs != "" {
		fmt.Fprintf(b, "     Needed: %s\n", it.Needs)
	}
	for _, p := range it.Patches {
		fmt.Fprintf(b, "     %s:%d  %s\n", p.File, p.Line, p.Summary)
	}
}

func planNextSteps(p Plan) []string {
	var out []string
	if p.Safe > 0 {
		out = append(out, "Apply the safe changes, then re-run the checks that found them: nox fix apply")
	}
	held := 0
	for i := range p.Items {
		if p.Items[i].Kind == KindHeldUpgrade {
			held++
		}
	}
	if p.Review > held {
		out = append(out, "Apply the changes that need review too, once you have looked: nox fix apply --include-review")
	}
	if held > 0 {
		out = append(out, "For a held upgrade, upgrade the package that pins it or add the entry named above to package.json, then re-run nox scan")
	}
	if p.Info > 0 {
		out = append(out, "Supply what the remaining issues need (listed above), then re-run nox scan")
	}
	out = append(out, "Check a change you made by hand: nox fix verify")
	return out
}

// WritePlanJSON writes the plan as indented JSON, the form CI and the MCP
// tool consume.
func WritePlanJSON(w io.Writer, p Plan) error {
	return writeJSON(w, p)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// RenderReport writes the verification report as plain text.
func RenderReport(w io.Writer, r Report) error {
	b := &strings.Builder{}
	b.WriteString("\nNox Fix Report\n\n")
	if len(r.Outcomes) == 0 {
		b.WriteString("No change was applied, so there is nothing to verify.\n")
		writeReportTail(b, r)
		_, err := io.WriteString(w, b.String())
		return err
	}
	fmt.Fprintf(b, "%s checked by re-running %s.\n", count(len(r.Outcomes), "change", "changes"), recheckedPhrase(r.Rechecked))
	groups := []struct {
		status Status
		head   string
	}{
		{StatusFixed, "Verified fixed"},
		{StatusStillPresent, "Still present"},
		{StatusNewFinding, "New finding introduced"},
		{StatusNotVerified, "Could not verify"},
		{StatusNotApplied, "Not applied"},
	}
	for _, g := range groups {
		var outs []*Outcome
		for i := range r.Outcomes {
			if r.Outcomes[i].Status == g.status {
				outs = append(outs, &r.Outcomes[i])
			}
		}
		if len(outs) == 0 {
			continue
		}
		fmt.Fprintf(b, "\n%s (%d):\n", g.head, len(outs))
		for _, o := range outs {
			fmt.Fprintf(b, "  %d. %s\n", o.N, o.Title)
			fmt.Fprintf(b, "     %s\n", o.Detail)
			for _, n := range o.New {
				fmt.Fprintf(b, "     New: %s\n", n)
			}
		}
	}
	writeReportTail(b, r)
	_, err := io.WriteString(w, b.String())
	return err
}

func writeReportTail(b *strings.Builder, r Report) {
	if len(r.NewElsewhere) > 0 {
		fmt.Fprintf(b, "\nAlso new in what was re-checked (%d), not tied to a change:\n", len(r.NewElsewhere))
		for _, n := range r.NewElsewhere {
			fmt.Fprintf(b, "  - %s\n", n)
		}
	}
	if len(r.NewInGeneratedDirs) > 0 {
		fmt.Fprintf(b, "\nAlso new inside directories a tool generated (%d), not attributed to your change:\n", len(r.NewInGeneratedDirs))
		fmt.Fprintf(b, "  The fix ran a package manager, which creates these; they were not in the original scan because the directory did not exist yet.\n")
		for _, n := range r.NewInGeneratedDirs {
			fmt.Fprintf(b, "  - %s\n", n)
		}
	}
	if len(r.Untouched) > 0 {
		fmt.Fprintf(b, "\nNot changed by nox, still yours to resolve: %s.\n", joinNumbers(r.Untouched))
	}
	fmt.Fprintf(b, "\n%s\n", r.Summary())
}

// Summary is the closing line: how many changes were observed to work, out of
// how many were attempted, never more.
func (r Report) Summary() string {
	if len(r.Outcomes) == 0 {
		return "Verified: 0 of 0 changes."
	}
	s := fmt.Sprintf("Verified fixed: %d of %d changes.", r.Counts.Fixed, len(r.Outcomes))
	if r.Counts.NotVerified > 0 {
		s += fmt.Sprintf(" %d could not be checked, so nothing is claimed for them.", r.Counts.NotVerified)
	}
	return s
}

// WriteReportJSON writes the report as indented JSON.
func WriteReportJSON(w io.Writer, r Report) error {
	return writeJSON(w, r)
}

func recheckedPhrase(scopes []string) string {
	if len(scopes) == 0 {
		return "the checks"
	}
	return "the " + strings.Join(scopes, " and ") + " checks"
}

func joinNumbers(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = fmt.Sprintf("%d", n)
	}
	if len(parts) == 1 {
		return "item " + parts[0]
	}
	return "items " + strings.Join(parts, ", ")
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
