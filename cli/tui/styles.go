package tui

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/nox-hq/nox/core/findings"
)

var (
	// Severity colors.
	colorCritical = lipgloss.Color("#FF0000")
	colorHigh     = lipgloss.Color("#FF8C00")
	colorMedium   = lipgloss.Color("#FFD700")
	colorLow      = lipgloss.Color("#4169E1")
	colorInfo     = lipgloss.Color("#808080")

	// UI colors.
	colorTitle    = lipgloss.Color("#FFFFFF")
	colorSubtle   = lipgloss.Color("#666666")
	colorSelected = lipgloss.Color("#7D56F4")
	colorMatch    = lipgloss.Color("#FF6B6B")

	// Styles.
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorTitle)

	subtleStyle = lipgloss.NewStyle().
			Foreground(colorSubtle)

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorSelected)

	matchLineStyle = lipgloss.NewStyle().
			Foreground(colorMatch)

	helpStyle = lipgloss.NewStyle().
			Foreground(colorSubtle)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(colorSubtle)

	ruleIDStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#AAAAAA"))

	fileStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#88C0D0"))

	remediationHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#A3BE8C"))

	cweStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#B48EAD"))
)

// severityStyle returns a styled severity badge.
func severityStyle(sev findings.Severity) lipgloss.Style {
	var color lipgloss.Color
	switch sev {
	case findings.SeverityCritical:
		color = colorCritical
	case findings.SeverityHigh:
		color = colorHigh
	case findings.SeverityMedium:
		color = colorMedium
	case findings.SeverityLow:
		color = colorLow
	default:
		color = colorInfo
	}
	return lipgloss.NewStyle().Bold(true).Foreground(color)
}

// severityBadge returns a short severity string for list display.
func severityBadge(sev findings.Severity) string {
	style := severityStyle(sev)
	switch sev {
	case findings.SeverityCritical:
		return style.Render("CRIT")
	case findings.SeverityHigh:
		return style.Render("HIGH")
	case findings.SeverityMedium:
		return style.Render(" MED")
	case findings.SeverityLow:
		return style.Render(" LOW")
	default:
		return style.Render("INFO")
	}
}
