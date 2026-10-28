package change

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/infra"
)

// DefaultLimit is how many lines each section lists before summarising the
// rest, matching the assessment's own cap.
const DefaultLimit = 5

// Render writes the delta as plain text under a "Since <label>:" heading. It
// reads nothing but d, so the same delta always renders to the same bytes. A
// limit of 0 lists every line.
func Render(w io.Writer, d Delta, limit int) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "\nSince %s:\n", d.Since)
	if d.Empty() {
		b.WriteString("  Nothing new and nothing resolved in what was compared.\n")
	}
	section(b, "New", len(d.New), findingLines(d.New), limit)
	section(b, "Resolved (no longer present)", len(d.Resolved), findingLines(d.Resolved), limit)
	section(b, "Waived or baselined since (not fixed)", len(d.Waived), findingLines(d.Waived), limit)

	var sev []string
	for _, c := range d.SeverityChanged {
		word := "lowered"
		if c.Regression {
			word = "raised"
		}
		sev = append(sev, fmt.Sprintf("%s %s: severity %s from %s to %s", c.RuleID, location(c.Item), word, c.From, c.To))
	}
	section(b, "Severity changed", len(sev), sev, limit)

	var ag []string
	for _, a := range d.Agents {
		ag = append(ag, agentLine(a))
	}
	section(b, "Agent capabilities", len(ag), ag, limit)

	weaker, stronger := infra.Split(d.Infrastructure)
	section(b, "Infrastructure assumptions weakened", len(weaker), infraLines(weaker), limit)
	section(b, "Infrastructure assumptions strengthened", len(stronger), infraLines(stronger), limit)

	var comps []string
	for _, c := range d.ComponentsAdded {
		comps = append(comps, fmt.Sprintf("added %s %q (%s)", c.Type, c.Name, c.Path))
	}
	for _, c := range d.ComponentsRemoved {
		comps = append(comps, fmt.Sprintf("removed %s %q (%s)", c.Type, c.Name, c.Path))
	}
	section(b, "AI components", len(comps), comps, limit)

	var nl []string
	for _, l := range d.NewLeads {
		nl = append(nl, fmt.Sprintf("%s: %s (%s:%d) %s", capitalize(l.Category), l.Route, l.FilePath, l.Line, l.Statement))
	}
	section(b, "New leads (to verify, not findings)", len(nl), nl, limit)
	var rl []string
	for _, l := range d.ResolvedLeads {
		rl = append(rl, fmt.Sprintf("%s: %s (%s)", capitalize(l.Category), l.Route, l.FilePath))
	}
	section(b, "Leads no longer present", len(rl), rl, limit)

	if len(d.Caveats) > 0 {
		b.WriteString("  Not compared / caution:\n")
		for _, c := range d.Caveats {
			fmt.Fprintf(b, "    - %s\n", c)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Text is Render into a string.
func Text(d Delta, limit int) string {
	b := &strings.Builder{}
	_ = Render(b, d, limit)
	return b.String()
}

func section(b *strings.Builder, title string, total int, lines []string, limit int) {
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s (%d):\n", title, total)
	shown := lines
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
	}
	for _, l := range shown {
		fmt.Fprintf(b, "    - %s\n", l)
	}
	if rest := len(lines) - len(shown); rest > 0 {
		fmt.Fprintf(b, "    ...and %d more; run with --verbose to list every one.\n", rest)
	}
}

// findingLines renders items, collapsing a package's advisories into one line:
// three new advisories for one package are one thing to fix, not three.
func findingLines(items []Item) []string {
	var order []string
	groups := map[string][]Item{}
	var lines []string
	var plain []Item
	for _, it := range items {
		if it.Advisory == "" {
			plain = append(plain, it)
			continue
		}
		k := it.File + "|" + it.Package + "|" + it.Version
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], it)
	}
	type rendered struct {
		rank int
		line string
	}
	var all []rendered
	for _, k := range order {
		g := groups[k]
		ids := make([]string, 0, len(g))
		best := g[0]
		for _, it := range g {
			ids = append(ids, it.Advisory)
			if findings.SeverityRank(findings.Severity(it.Severity)) < findings.SeverityRank(findings.Severity(best.Severity)) {
				best = it
			}
		}
		sort.Strings(ids)
		noun := "advisory"
		if len(g) != 1 {
			noun = "advisories"
		}
		all = append(all, rendered{
			rank: findings.SeverityRank(findings.Severity(best.Severity)),
			line: fmt.Sprintf("[%s] %d %s for %s@%s (%s): %s", strings.ToUpper(best.Severity), len(g), noun, best.Package, best.Version, best.File, strings.Join(ids, ", ")),
		})
	}
	for _, it := range plain {
		all = append(all, rendered{
			rank: findings.SeverityRank(findings.Severity(it.Severity)),
			line: fmt.Sprintf("[%s] %s %s: %s", strings.ToUpper(it.Severity), it.RuleID, location(it), oneLine(it.Message)),
		})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].rank < all[j].rank })
	for _, r := range all {
		lines = append(lines, r.line)
	}
	return lines
}

func infraLines(cs []infra.Change) []string {
	lines := make([]string, 0, len(cs))
	for _, c := range cs {
		lines = append(lines, c.Line())
	}
	return lines
}

func location(it Item) string {
	if it.Line > 0 {
		return it.File + ":" + strconv.Itoa(it.Line)
	}
	return it.File
}

func oneLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	const maxLine = 140
	if len(s) > maxLine {
		s = s[:maxLine-3] + "..."
	}
	return s
}

func agentLine(a AgentChange) string {
	who := "Agent " + a.Agent
	if a.Server != "" {
		who += " (server " + a.Server + ")"
	}
	if a.Path != "" {
		who += " [" + a.Path + "]"
	}
	switch {
	case a.Removed:
		return who + " is gone; it held " + grantWords(a.Lost) + "."
	case a.Added:
		return "New " + strings.ToLower(who[:1]) + who[1:] + " with " + grantWords(a.Gained) + "."
	}
	var parts []string
	if len(a.Gained) > 0 {
		parts = append(parts, "gained "+grantWords(a.Gained))
	}
	if len(a.Lost) > 0 {
		parts = append(parts, "lost "+grantWords(a.Lost))
	}
	return who + " " + strings.Join(parts, " and ") + "."
}

// grantWords renders grants as "shell_exec (tool run_shell), email_send (tool
// send_email)"; a tool with no known capability is named as the tool alone.
func grantWords(gs []Grant) string {
	var parts []string
	for _, g := range gs {
		if len(g.Capabilities) == 0 {
			parts = append(parts, "tool "+g.Tool)
			continue
		}
		for _, c := range g.Capabilities {
			parts = append(parts, c+" (tool "+g.Tool+")")
		}
	}
	if len(parts) == 0 {
		return "no tools"
	}
	return strings.Join(parts, ", ")
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
