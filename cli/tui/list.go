package tui

import (
	"fmt"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// renderList renders the finding list view.
func renderList(m *Model) string {
	var b strings.Builder

	// Header.
	title := titleStyle.Render(fmt.Sprintf(" Nox — %d findings", len(m.filtered)))
	if m.store.Count() != len(m.filtered) {
		title += subtleStyle.Render(fmt.Sprintf(" (of %d total)", m.store.Count()))
	}
	b.WriteString(title)
	b.WriteString("\n")
	b.WriteString(headerStyle.Render(strings.Repeat("─", m.width)))
	b.WriteString("\n")

	// Filter status.
	filterLine := subtleStyle.Render(" Filter: ") +
		"[" + m.filter.activeSeverity() + "]"
	if m.filter.search != "" {
		filterLine += subtleStyle.Render("  Search: ") + "[" + m.filter.search + "]"
	}
	b.WriteString(filterLine)
	b.WriteString("\n\n")

	// Finding list.
	if len(m.filtered) == 0 {
		b.WriteString(subtleStyle.Render("  No findings match the current filters.\n"))
	} else {
		// Calculate visible window.
		visibleLines := m.height - 8 // Header + filter + help lines.
		if visibleLines < 1 {
			visibleLines = 1
		}
		start := m.cursor - visibleLines/2
		if start < 0 {
			start = 0
		}
		end := start + visibleLines
		if end > len(m.filtered) {
			end = len(m.filtered)
			start = end - visibleLines
			if start < 0 {
				start = 0
			}
		}

		for i := start; i < end; i++ {
			f := m.filtered[i]
			line := renderFindingLine(f, i == m.cursor)
			b.WriteString(line)
			b.WriteString("\n")
		}
	}

	// Search input.
	if m.filter.searching {
		b.WriteString("\n")
		b.WriteString(" Search: " + m.filter.search + "█")
		b.WriteString("\n")
	}

	// Help.
	b.WriteString("\n")
	b.WriteString(helpStyle.Render(" ↑↓ navigate  enter detail  / search  s severity  q quit"))
	b.WriteString("\n")

	return b.String()
}

// renderFindingLine renders a single finding line in the list.
func renderFindingLine(f findings.Finding, selected bool) string {
	badge := severityBadge(f.Severity)
	ruleID := ruleIDStyle.Render(fmt.Sprintf("%-7s", f.RuleID))

	fileLoc := f.Location.FilePath
	if f.Location.StartLine > 0 {
		fileLoc = fmt.Sprintf("%s:%d", f.Location.FilePath, f.Location.StartLine)
	}
	file := fileStyle.Render(fmt.Sprintf("%-30s", fileLoc))

	line := fmt.Sprintf(" %s  %s  %s  %s", badge, ruleID, file, f.Message)

	if selected {
		return selectedStyle.Render("▸") + line
	}
	return " " + line
}
