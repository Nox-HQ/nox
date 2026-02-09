package tui

import (
	"fmt"
	"strings"

	coredetail "github.com/nox-hq/nox/core/detail"
)

// renderDetail renders the detail view for a single finding.
func renderDetail(m *Model) string {
	if m.cursor < 0 || m.cursor >= len(m.filtered) {
		return "No finding selected."
	}

	f := m.filtered[m.cursor]
	d := coredetail.Enrich(f, m.store.BasePath(), m.store.All(), m.catalog, m.contextLines)

	var b strings.Builder

	// Header.
	sevBadge := severityStyle(f.Severity).Render(strings.ToUpper(string(f.Severity)))
	b.WriteString(fmt.Sprintf(" %s · %s · %s\n",
		ruleIDStyle.Render(f.RuleID),
		f.Message,
		sevBadge))
	b.WriteString(headerStyle.Render(strings.Repeat("─", m.width)))
	b.WriteString("\n")

	// File location.
	fileLoc := f.Location.FilePath
	if f.Location.StartLine > 0 {
		fileLoc = fmt.Sprintf("%s:%d", f.Location.FilePath, f.Location.StartLine)
	}
	b.WriteString(" " + fileStyle.Render(fileLoc) + "\n\n")

	// Source context.
	if d.Source != nil && len(d.Source.Lines) > 0 {
		for _, line := range d.Source.Lines {
			prefix := "  "
			if line.IsMatch {
				prefix = matchLineStyle.Render("→ ")
			}
			lineNum := subtleStyle.Render(fmt.Sprintf("%4d │ ", line.Number))
			text := line.Text
			if line.IsMatch {
				text = matchLineStyle.Render(text)
			}
			b.WriteString(prefix + lineNum + text + "\n")
		}
		b.WriteString("\n")
	}

	// CWE.
	if d.Rule != nil && d.Rule.CWE != "" {
		b.WriteString(" " + cweStyle.Render("CWE: "+d.Rule.CWE) + "\n\n")
	}

	// Remediation.
	if d.Rule != nil && d.Rule.Remediation != "" {
		b.WriteString(" " + remediationHeaderStyle.Render("Remediation") + "\n")
		b.WriteString(wrapText(d.Rule.Remediation, m.width-4, "   "))
		b.WriteString("\n")
	}

	// References.
	if d.Rule != nil && len(d.Rule.References) > 0 {
		b.WriteString(" " + remediationHeaderStyle.Render("References") + "\n")
		for _, ref := range d.Rule.References {
			b.WriteString("   " + subtleStyle.Render(ref) + "\n")
		}
		b.WriteString("\n")
	}

	// Related findings.
	if len(d.Related) > 0 {
		b.WriteString(" " + remediationHeaderStyle.Render("Related") + "\n")
		for _, rel := range d.Related {
			relLoc := rel.FilePath
			if rel.Line > 0 {
				relLoc = fmt.Sprintf("%s:%d", rel.FilePath, rel.Line)
			}
			b.WriteString(fmt.Sprintf("   %s  %s  %s\n",
				ruleIDStyle.Render(rel.RuleID),
				fileStyle.Render(relLoc),
				rel.Message))
		}
		b.WriteString("\n")
	}

	// Metadata.
	if len(f.Metadata) > 0 {
		b.WriteString(" " + remediationHeaderStyle.Render("Metadata") + "\n")
		for k, v := range f.Metadata {
			b.WriteString(fmt.Sprintf("   %s: %s\n", subtleStyle.Render(k), v))
		}
		b.WriteString("\n")
	}

	// Help.
	b.WriteString(helpStyle.Render(" esc back  n/p next/prev  q quit"))
	b.WriteString("\n")

	return b.String()
}

// wrapText wraps text at the given width with the given indent prefix.
func wrapText(text string, width int, indent string) string {
	if width <= 0 {
		width = 78
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(indent)
	lineLen := len(indent)

	for i, word := range words {
		if i > 0 && lineLen+1+len(word) > width {
			b.WriteString("\n" + indent)
			lineLen = len(indent)
		} else if i > 0 {
			b.WriteString(" ")
			lineLen++
		}
		b.WriteString(word)
		lineLen += len(word)
	}
	b.WriteString("\n")
	return b.String()
}
