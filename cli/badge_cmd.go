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
		findingsList = result.Findings.Findings()
		fmt.Printf("[results] %d findings\n", len(findingsList))
	}

	counts := countBySeverity(findingsList)
	maxSev := maxSeverity(findingsList)
	value := badgeValue(len(findingsList), maxSev, counts)
	color := badgeColor(maxSev, len(findingsList))

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

// severityRank maps severity to a numeric rank for comparison.
var severityRank = map[findings.Severity]int{
	findings.SeverityCritical: 5,
	findings.SeverityHigh:     4,
	findings.SeverityMedium:   3,
	findings.SeverityLow:      2,
	findings.SeverityInfo:     1,
}

func countBySeverity(ff []findings.Finding) map[findings.Severity]int {
	counts := make(map[findings.Severity]int)
	for _, f := range ff {
		counts[f.Severity]++
	}
	return counts
}

func maxSeverity(ff []findings.Finding) findings.Severity {
	best := findings.Severity("")
	bestRank := 0
	for _, f := range ff {
		r := severityRank[f.Severity]
		if r > bestRank {
			bestRank = r
			best = f.Severity
		}
	}
	return best
}

func badgeValue(total int, maxSev findings.Severity, counts map[findings.Severity]int) string {
	if total == 0 {
		return "clean"
	}
	n := counts[maxSev]
	if n == total {
		return fmt.Sprintf("%d %s", total, maxSev)
	}
	return fmt.Sprintf("%d %s · %d total", n, maxSev, total)
}

func badgeColor(maxSev findings.Severity, total int) string {
	if total == 0 {
		return "#4c1" // bright green
	}
	switch maxSev {
	case findings.SeverityCritical:
		return "#e05d44" // red
	case findings.SeverityHigh:
		return "#fe7d37" // orange
	case findings.SeverityMedium:
		return "#dfb317" // yellow
	case findings.SeverityLow:
		return "#a3c51c" // yellow-green
	case findings.SeverityInfo:
		return "#9f9f9f" // gray
	default:
		return "#9f9f9f"
	}
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
