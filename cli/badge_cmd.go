package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

// runBadge implements the "nox badge" command.
func runBadge(args []string) int {
	var flagArgs []string
	var positionalArgs []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flagArgs = append(flagArgs, args[i])
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			positionalArgs = append(positionalArgs, args[i])
		}
	}

	fs := flag.NewFlagSet("badge", flag.ContinueOnError)

	var (
		input  string
		output string
		label  string
	)

	fs.StringVar(&input, "input", "", "path to findings.json (default: run scan)")
	fs.StringVar(&output, "output", ".github/nox-badge.svg", "output SVG file path")
	fs.StringVar(&label, "label", "nox", "badge label text")

	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	positionalArgs = append(positionalArgs, fs.Args()...)

	var findingsList []findings.Finding

	if input != "" {
		data, err := os.ReadFile(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", input, err)
			return 2
		}
		var rep report.JSONReport
		if err := json.Unmarshal(data, &rep); err != nil {
			fmt.Fprintf(os.Stderr, "error: parsing findings JSON: %v\n", err)
			return 2
		}
		findingsList = rep.Findings
	} else {
		target := "."
		if len(positionalArgs) > 0 {
			target = positionalArgs[0]
		}
		fmt.Printf("nox — scanning %s\n", target)
		result, err := nox.RunScan(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
			return 2
		}
		findingsList = result.Findings.ActiveFindings()
		suppressed := len(result.Findings.Findings()) - len(findingsList)
		if suppressed > 0 {
			fmt.Printf("[results] %d findings (%d suppressed)\n", len(findingsList), suppressed)
		} else {
			fmt.Printf("[results] %d findings\n", len(findingsList))
		}
	}

	counts := countBySeverity(findingsList)
	value := badgeValue(counts)
	color := badgeColor(counts)

	svg := generateBadgeSVG(label, value, color)

	// Ensure parent directory exists.
	if dir := dirOf(output); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error: creating directory %s: %v\n", dir, err)
			return 2
		}
	}

	if err := os.WriteFile(output, []byte(svg), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}

	fmt.Printf("[badge] wrote %s (%s: %s)\n", output, label, value)
	return 0
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}

func countBySeverity(ff []findings.Finding) map[findings.Severity]int {
	counts := make(map[findings.Severity]int)
	for _, f := range ff {
		counts[f.Severity]++
	}
	return counts
}

// severityWeight maps severity to a point value for scoring.
var severityWeight = map[findings.Severity]int{
	findings.SeverityCritical: 10,
	findings.SeverityHigh:     5,
	findings.SeverityMedium:   2,
	findings.SeverityLow:      1,
	findings.SeverityInfo:     0,
}

// securityScore computes a weighted score from finding severity counts.
func securityScore(counts map[findings.Severity]int) int {
	score := 0
	for sev, n := range counts {
		score += severityWeight[sev] * n
	}
	return score
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
	{0, Grade{"A", "#4c1"}},      // bright green
	{4, Grade{"B", "#a3c51c"}},   // yellow-green
	{14, Grade{"C", "#dfb317"}},  // yellow
	{29, Grade{"D", "#fe7d37"}},  // orange
	{49, Grade{"E", "#e05d44"}},  // red
}

var gradeF = Grade{"F", "#b60205"} // dark red

// gradeFromScore returns the letter grade for a given score.
func gradeFromScore(score int) Grade {
	for _, t := range gradeThresholds {
		if score <= t.maxScore {
			return t.grade
		}
	}
	return gradeF
}

func badgeValue(counts map[findings.Severity]int) string {
	score := securityScore(counts)
	return gradeFromScore(score).Letter
}

func badgeColor(counts map[findings.Severity]int) string {
	score := securityScore(counts)
	return gradeFromScore(score).Color
}

// badgeTextWidth estimates the pixel width of a string rendered in Verdana 11px,
// matching the shields.io flat badge style.
func badgeTextWidth(s string) int {
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

func generateBadgeSVG(label, value, color string) string {
	labelW := badgeTextWidth(label) + 10
	valueW := badgeTextWidth(value) + 10
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
