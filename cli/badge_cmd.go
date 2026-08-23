package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/badge"
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
		input      string
		output     string
		label      string
		bySeverity bool
		explain    bool
	)

	fs.StringVar(&input, "input", "", "path to findings.json (default: run scan)")
	fs.StringVar(&output, "output", ".github/nox-badge.svg", "output SVG file path")
	fs.StringVar(&label, "label", "nox", "badge label text")
	fs.BoolVar(&bySeverity, "by-severity", false, "generate additional badges per severity level")
	fs.BoolVar(&explain, "explain", false, "print per-finding score contributions instead of writing the badge")

	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	positionalArgs = append(positionalArgs, fs.Args()...)

	var findingsList []findings.Finding

	if input != "" {
		// Include only active findings, via the shared loader + projection —
		// VEX-waived and baselined findings must not inflate the badge grade.
		rep, err := report.LoadFindingsFileReport(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", input, err)
			return 2
		}
		findingsList = rep.ActiveFindings()
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

	badgeResult := badge.GenerateFromFindings(findingsList, label)

	if explain {
		printBadgeExplain(findingsList, badgeResult)
		return 0
	}

	// Ensure parent directory exists.
	if dir := filepath.Dir(output); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error: creating directory %s: %v\n", dir, err)
			return 2
		}
	}

	if err := os.WriteFile(output, []byte(badgeResult.SVG), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}

	fmt.Printf("[badge] wrote %s (%s: %s)\n", output, label, badgeResult.Value)

	// Generate per-severity badges if requested.
	if bySeverity {
		dir := filepath.Dir(output)
		sevBadges := badge.SeverityBadges(findingsList, label)
		for _, sev := range badge.SeverityOrder {
			b := sevBadges[sev]
			path := filepath.Join(dir, fmt.Sprintf("nox-%s.svg", sev))
			if err := os.WriteFile(path, []byte(b.SVG), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", path, err)
				return 2
			}
			fmt.Printf("[badge] wrote %s (%s: %s)\n", path, b.Label, b.Value)
		}
	}

	return 0
}

// printBadgeExplain prints a human-readable breakdown of how the security
// score was computed: total, grade, formula, and the per-finding
// contributions sorted by points descending. Surfaces the score formula so
// users can decide whether to fix vs baseline vs ignore — issue #62.
func printBadgeExplain(ff []findings.Finding, result *badge.Result) {
	score, contribs := badge.WeightedSecurityScore(ff)

	fmt.Printf("Score: %d  Grade: %s  Findings: %d\n",
		score, result.Grade, len(ff))
	fmt.Println("Formula: ceil( sum( severity_weight * confidence_weight ) )")
	fmt.Println("  severity_weight   critical=10  high=5  medium=2  low=1  info=0")
	fmt.Println("  confidence_weight high=1.0     medium=0.5  low=0.2")

	if len(contribs) == 0 {
		fmt.Println("\nNo active findings.")
		return
	}

	fmt.Println()
	fmt.Printf("%-14s  %-9s  %-10s  %5s  %5s  %7s  %s\n",
		"RULE", "SEVERITY", "CONFIDENCE", "SEV-W", "CONF-W", "POINTS", "LOCATION")
	fmt.Println(strings.Repeat("-", 90))
	for _, c := range contribs {
		fmt.Printf("%-14s  %-9s  %-10s  %5d  %5.1f  %7.2f  %s\n",
			c.RuleID, string(c.Severity), string(c.Confidence),
			c.SeverityW, c.ConfidenceW, c.Points, c.Location)
	}
}
