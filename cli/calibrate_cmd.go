package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"

	"github.com/nox-hq/nox/core/catalog"
)

// runCalibrate consumes a nox bench report and recommends rule
// severity overrides. The premise: severity is a static property at
// rule-definition time, but actual signal value is empirical. Rules
// that fire on most projects in a diverse corpus are noise regardless
// of their nominal severity — calibration corrects for that.
//
// Output is a `.nox.yaml` snippet operators can paste into their
// project config; the snippet uses the existing rules.severity_override
// mechanism so no new schema is required.
func runCalibrate(args []string) int {
	fs := flag.NewFlagSet("calibrate", flag.ContinueOnError)
	var (
		benchPath  string
		output     string
		highT      float64
		lowT       float64
		noiseFloor int
	)
	fs.StringVar(&benchPath, "bench", "", "path to nox bench JSON report (required)")
	fs.StringVar(&output, "output", "", "destination YAML path (defaults to stdout)")
	fs.Float64Var(&highT, "noise-threshold", 0.8, "rules firing in this fraction of projects are flagged as noise")
	fs.Float64Var(&lowT, "signal-threshold", 0.05, "rules firing in less than this fraction are flagged as signal-strong")
	fs.IntVar(&noiseFloor, "min-projects", 3, "minimum project count for the corpus to produce calibration recommendations")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if benchPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: nox calibrate --bench <bench.json> [--output suggested.yaml]")
		return 2
	}

	raw, err := os.ReadFile(benchPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", benchPath, err)
		return 2
	}
	var report BenchReport
	if err := json.Unmarshal(raw, &report); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", benchPath, err)
		return 2
	}

	totalProjects := len(report.Projects)
	if totalProjects < noiseFloor {
		fmt.Fprintf(os.Stderr, "warn: only %d projects in corpus; recommend %d minimum for stable calibration. Continuing anyway.\n", totalProjects, noiseFloor)
	}
	if totalProjects == 0 {
		return 0
	}

	cat := catalog.Catalog()
	var recs []recommendation

	for rule, count := range report.RuleFireRate {
		rate := float64(count) / float64(totalProjects)
		meta, hasMeta := cat[rule]
		current := ""
		if hasMeta {
			current = meta.Severity
		}

		switch {
		case rate >= highT:
			next := string(findings.Severity(current).Downgraded())
			if next == current || current == "" {
				continue
			}
			recs = append(recs, recommendation{
				ruleID:      rule,
				current:     current,
				recommended: next,
				fireRate:    rate,
				reason:      fmt.Sprintf("fires on %.0f%% of corpus — likely noise at current severity", rate*100),
			})
		case rate <= lowT && current != "" && current != "critical":
			next := string(findings.Severity(current).Upgraded())
			if next == current {
				continue
			}
			recs = append(recs, recommendation{
				ruleID:      rule,
				current:     current,
				recommended: next,
				fireRate:    rate,
				reason:      fmt.Sprintf("fires on %.0f%% of corpus — signal-strong, consider promoting", rate*100),
			})
		}
	}

	sort.Slice(recs, func(i, j int) bool {
		if recs[i].fireRate != recs[j].fireRate {
			return recs[i].fireRate > recs[j].fireRate
		}
		return recs[i].ruleID < recs[j].ruleID
	})

	yaml := renderCalibrateYAML(recs, totalProjects)
	if output == "" {
		fmt.Print(yaml)
		return 0
	}
	if err := os.WriteFile(output, []byte(yaml), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "[calibrate] wrote %s (%d recommendations across %d projects)\n", output, len(recs), totalProjects)
	return 0
}

// demote returns the severity one level below current. critical->high
// ->medium->low->info->info.
// promote returns the severity one level above current.
// recommendation is the per-rule calibration outcome.
type recommendation struct {
	ruleID      string
	current     string
	recommended string
	fireRate    float64
	reason      string
}

// renderCalibrateYAML produces a .nox.yaml fragment using the
// rules.severity_override mechanism from the existing ScanConfig.
// Fragments are commented per-rule with the empirical reason so a
// reviewer can decide whether to keep each override.
func renderCalibrateYAML(recs []recommendation, totalProjects int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Suggested severity overrides derived from nox bench (%d projects).\n", totalProjects)
	b.WriteString("# Paste under the `scan.rules` section of your .nox.yaml.\n")
	b.WriteString("# Review each entry — empirical fire-rate doesn't always mean noise.\n\n")

	if len(recs) == 0 {
		b.WriteString("# No recommendations: all rules fall between the noise / signal thresholds.\n")
		return b.String()
	}

	b.WriteString("scan:\n  rules:\n    severity_override:\n")
	for _, r := range recs {
		fmt.Fprintf(&b, "      # %s (was %s, %s)\n", r.reason, r.current, r.recommended)
		fmt.Fprintf(&b, "      %s: %s\n", r.ruleID, r.recommended)
	}
	return b.String()
}
