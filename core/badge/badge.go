// Package badge generates SVG status badges from security findings.
// It provides scoring, grading, and SVG generation used by both CLI
// and MCP server.
package badge

import (
	"encoding/xml"
	"fmt"
	"math"
	"strings"

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

// ConfidenceWeight scales each finding's contribution to the security score
// by how sure the rule itself is. Low-confidence pattern matches no longer
// tank the grade as hard as confirmed high-severity issues — see issue #62.
//
// A missing or unknown confidence value defaults to 1.0 so older rules that
// haven't declared a confidence still count fully. New rules should set an
// explicit confidence.
var ConfidenceWeight = map[findings.Confidence]float64{
	findings.ConfidenceHigh:   1.0,
	findings.ConfidenceMedium: 0.5,
	findings.ConfidenceLow:    0.2,
}

// confidenceWeight returns the multiplier for a given confidence, defaulting
// to 1.0 when the value is empty or unrecognised.
func confidenceWeight(c findings.Confidence) float64 {
	if w, ok := ConfidenceWeight[c]; ok {
		return w
	}
	return 1.0
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

// SeverityOrder is the order severity badges are generated in, derived from the
// canonical findings.SeverityOrder and filtered to the severities that have a
// badge colour. Deriving it rather than re-declaring means adding a severity
// upstream cannot leave this list stale — it just needs a colour to appear.
var SeverityOrder = func() []findings.Severity {
	var out []findings.Severity
	for _, s := range findings.SeverityOrder {
		if _, ok := SeverityBadgeColors[s]; ok {
			out = append(out, s)
		}
	}
	return out
}()

// CountBySeverity tallies findings by severity level. It delegates to the
// domain so badge, policy, and any other caller share one tally.
func CountBySeverity(ff []findings.Finding) map[findings.Severity]int {
	return findings.CountBySeverity(ff)
}

// SecurityScore computes a severity-weighted score from finding counts.
// It is preserved for callers that work from pre-tallied severity counts and
// have no confidence information; new code should prefer
// WeightedSecurityScore which also factors in rule confidence.
func SecurityScore(counts map[findings.Severity]int) int {
	score := 0
	for sev, n := range counts {
		score += SeverityWeight[sev] * n
	}
	return score
}

// Contribution describes how a single finding contributed to the
// WeightedSecurityScore. Returned by Explain so users can see why their
// grade is what it is — see issue #62 (`nox badge --explain`).
type Contribution struct {
	RuleID      string              `json:"rule_id"`
	Severity    findings.Severity   `json:"severity"`
	Confidence  findings.Confidence `json:"confidence"`
	SeverityW   int                 `json:"severity_weight"`
	ConfidenceW float64             `json:"confidence_weight"`
	Points      float64             `json:"points"`
	Location    string              `json:"location,omitempty"`
}

// WeightedSecurityScore computes the score as
//
//	sum( SeverityWeight[severity] * ConfidenceWeight[confidence] )
//
// over all findings, rounded up to the next integer. Low-confidence pattern
// matches now contribute proportionally less than confirmed high-confidence
// findings, which prevents a clean repo from grading E off a handful of
// uncertain regex hits.
//
// Returns the rounded score and the per-finding contributions (sorted by
// descending points) for use by --explain output.
func WeightedSecurityScore(ff []findings.Finding) (int, []Contribution) {
	contribs := make([]Contribution, 0, len(ff))
	var total float64
	for i := range ff {
		f := &ff[i]
		sw := SeverityWeight[f.Severity]
		cw := confidenceWeight(f.Confidence)
		pts := float64(sw) * cw
		total += pts
		loc := ""
		if f.Location.FilePath != "" {
			loc = fmt.Sprintf("%s:%d", f.Location.FilePath, f.Location.StartLine)
		}
		contribs = append(contribs, Contribution{
			RuleID:      f.RuleID,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
			SeverityW:   sw,
			ConfidenceW: cw,
			Points:      pts,
			Location:    loc,
		})
	}
	sortContributionsDesc(contribs)
	return int(math.Ceil(total)), contribs
}

// sortContributionsDesc sorts contributions by points descending, then by
// rule ID ascending for stable output.
func sortContributionsDesc(c []Contribution) {
	for i := 1; i < len(c); i++ {
		for j := i; j > 0; j-- {
			if c[j].Points > c[j-1].Points ||
				(c[j].Points == c[j-1].Points && c[j].RuleID < c[j-1].RuleID) {
				c[j], c[j-1] = c[j-1], c[j]
				continue
			}
			break
		}
	}
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
// The score is confidence-weighted so low-confidence pattern matches don't
// disproportionately tank the grade — see issue #62.
func GenerateFromFindings(ff []findings.Finding, label string) *Result {
	score, _ := WeightedSecurityScore(ff)
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

// escapeXML escapes text for safe inclusion in an SVG/XML attribute or element.
func escapeXML(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// GenerateSVG produces an SVG badge string for the given label, value, and color.
func GenerateSVG(label, value, color string) string {
	// Widths are measured on the raw text (visual glyph count), but the text is
	// XML-escaped before it goes into the SVG. A label containing '&', '<', '>'
	// or '"' — a user-supplied --label — would otherwise produce malformed XML
	// or allow markup injection into the badge.
	labelW := textWidth(label) + 10
	valueW := textWidth(value) + 10
	totalW := labelW + valueW

	label = escapeXML(label)
	value = escapeXML(value)

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
