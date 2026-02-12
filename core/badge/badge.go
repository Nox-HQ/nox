// Package badge generates SVG status badges from security findings.
// It provides scoring, grading, and SVG generation used by both CLI
// and MCP server.
package badge

import (
	"fmt"
	"math"

	"github.com/nox-hq/nox/core/findings"
)

// Result holds badge generation output.
type Result struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Color string `json:"color"`
	Grade string `json:"grade"`
	Score int    `json:"score"`
	SVG   string `json:"svg,omitempty"`
}

// SeverityWeight maps severity to a point value for scoring.
var SeverityWeight = map[findings.Severity]int{
	findings.SeverityCritical: 10,
	findings.SeverityHigh:     5,
	findings.SeverityMedium:   2,
	findings.SeverityLow:      1,
	findings.SeverityInfo:     0,
}

// Grade represents a security letter grade A through F.
type Grade struct {
	Letter string
	Color  string
}

// gradeThresholds maps score ranges to letter grades and badge colors.
var gradeThresholds = []struct {
	maxScore int
	grade    Grade
}{
	{0, Grade{"A", "#4c1"}},     // bright green
	{4, Grade{"B", "#a3c51c"}},  // yellow-green
	{14, Grade{"C", "#dfb317"}}, // yellow
	{29, Grade{"D", "#fe7d37"}}, // orange
	{49, Grade{"E", "#e05d44"}}, // red
}

var gradeF = Grade{"F", "#b60205"} // dark red

// SeverityBadgeColors maps severity levels to badge colors for non-zero counts.
var SeverityBadgeColors = map[findings.Severity]string{
	findings.SeverityCritical: "#b60205",
	findings.SeverityHigh:     "#e05d44",
	findings.SeverityMedium:   "#dfb317",
	findings.SeverityLow:      "#a3c51c",
}

// SeverityOrder defines the order in which severity badges are generated.
var SeverityOrder = []findings.Severity{
	findings.SeverityCritical,
	findings.SeverityHigh,
	findings.SeverityMedium,
	findings.SeverityLow,
}

// CountBySeverity tallies findings by severity level.
func CountBySeverity(ff []findings.Finding) map[findings.Severity]int {
	counts := make(map[findings.Severity]int)
	for i := range ff {
		counts[ff[i].Severity]++
	}
	return counts
}

// SecurityScore computes a weighted score from finding severity counts.
func SecurityScore(counts map[findings.Severity]int) int {
	score := 0
	for sev, n := range counts {
		score += SeverityWeight[sev] * n
	}
	return score
}

// GradeFromScore returns the letter grade for a given score.
func GradeFromScore(score int) Grade {
	for _, t := range gradeThresholds {
		if score <= t.maxScore {
			return t.grade
		}
	}
	return gradeF
}

// GenerateFromFindings creates a badge result from a set of findings.
func GenerateFromFindings(ff []findings.Finding, label string) *Result {
	counts := CountBySeverity(ff)
	score := SecurityScore(counts)
	grade := GradeFromScore(score)

	return &Result{
		Label: label,
		Value: grade.Letter,
		Color: grade.Color,
		Grade: grade.Letter,
		Score: score,
		SVG:   GenerateSVG(label, grade.Letter, grade.Color),
	}
}

// SeverityBadges generates per-severity badge results.
func SeverityBadges(ff []findings.Finding, label string) map[findings.Severity]*Result {
	counts := CountBySeverity(ff)
	results := make(map[findings.Severity]*Result)

	for _, sev := range SeverityOrder {
		count := counts[sev]
		sevName := string(sev)
		badgeLabel := label + " " + sevName
		badgeValue := fmt.Sprintf("%d", count)

		color := "#4c1" // green for zero
		if count > 0 {
			color = SeverityBadgeColors[sev]
		}

		results[sev] = &Result{
			Label: badgeLabel,
			Value: badgeValue,
			Color: color,
			SVG:   GenerateSVG(badgeLabel, badgeValue, color),
		}
	}

	return results
}

// GenerateSVG produces an SVG badge string for the given label, value, and color.
func GenerateSVG(label, value, color string) string {
	labelW := textWidth(label) + 10
	valueW := textWidth(value) + 10
	totalW := labelW + valueW

	// Text positions are in tenths of a pixel (SVG uses scale(.1)).
	labelX := labelW * 10 / 2
	valueX := (labelW + valueW/2) * 10

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="%d" height="20" role="img" aria-label="%s: %s">
  <title>%s: %s</title>
  <linearGradient id="s" x2="0" y2="100%%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="%d" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="%d" height="20" fill="#555"/>
    <rect x="%d" width="%d" height="20" fill="%s"/>
    <rect width="%d" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">%s</text>
    <text x="%d" y="140" transform="scale(.1)">%s</text>
    <text aria-hidden="true" x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">%s</text>
    <text x="%d" y="140" transform="scale(.1)">%s</text>
  </g>
</svg>
`,
		totalW, label, value,
		label, value,
		totalW,
		labelW,
		labelW, valueW, color,
		totalW,
		labelX, label,
		labelX, label,
		valueX, value,
		valueX, value,
	)
}

// textWidth estimates the pixel width of a string rendered in Verdana 11px,
// matching the shields.io flat badge style.
func textWidth(s string) int {
	w := 0.0
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			w += 7.5
		case c >= 'a' && c <= 'z':
			w += 6.1
		case c >= '0' && c <= '9':
			w += 6.5
		case c == ' ':
			w += 3.3
		default:
			w += 6.0
		}
	}
	return int(math.Ceil(w))
}
