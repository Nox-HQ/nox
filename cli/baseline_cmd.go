package main

import (
	"flag"
	"fmt"
	"os"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/baseline"
)

func runBaseline(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox baseline <write|update|show> [path]")
		return 2
	}

	subcommand := args[0]
	remaining := args[1:]

	switch subcommand {
	case "write":
		return baselineWrite(remaining)
	case "update":
		return baselineUpdate(remaining)
	case "show":
		return baselineShow(remaining)
	default:
		fmt.Fprintf(os.Stderr, "unknown baseline subcommand: %s\n", subcommand)
		fmt.Fprintln(os.Stderr, "Usage: nox baseline <write|update|show> [path]")
		return 2
	}
}

func baselineWrite(args []string) int {
	fs := flag.NewFlagSet("baseline write", flag.ContinueOnError)
	var outputPath string
	fs.StringVar(&outputPath, "output", "", "baseline file path (default: .nox/baseline.json)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	if outputPath == "" {
		outputPath = baseline.DefaultPath(target)
	}

	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	ff := result.Findings.Findings()
	bl := &baseline.Baseline{}
	for _, e := range baseline.FromFindings(ff) {
		bl.Add(e)
	}

	if err := bl.Save(outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing baseline: %v\n", err)
		return 2
	}

	fmt.Printf("baseline: wrote %d entries to %s\n", bl.Len(), outputPath)
	return 0
}

func baselineUpdate(args []string) int {
	fs := flag.NewFlagSet("baseline update", flag.ContinueOnError)
	var baselinePath string
	fs.StringVar(&baselinePath, "baseline", "", "baseline file path (default: .nox/baseline.json)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	if baselinePath == "" {
		baselinePath = baseline.DefaultPath(target)
	}

	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	bl, err := baseline.Load(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading baseline: %v\n", err)
		return 2
	}

	ff := result.Findings.Findings()

	// Add new findings not already in baseline.
	added := 0
	existing := make(map[string]struct{}, bl.Len())
	for _, e := range bl.Entries {
		existing[e.Fingerprint] = struct{}{}
	}
	for _, e := range baseline.FromFindings(ff) {
		if _, ok := existing[e.Fingerprint]; !ok {
			bl.Add(e)
			existing[e.Fingerprint] = struct{}{}
			added++
		}
	}

	// Prune stale entries.
	pruned := bl.Prune(ff)

	if err := bl.Save(baselinePath); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving baseline: %v\n", err)
		return 2
	}

	fmt.Printf("baseline: %d total, %d added, %d pruned — %s\n", bl.Len(), added, pruned, baselinePath)
	return 0
}

func baselineShow(args []string) int {
	fs := flag.NewFlagSet("baseline show", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	baselinePath := baseline.DefaultPath(target)
	bl, err := baseline.Load(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading baseline: %v\n", err)
		return 2
	}

	if bl.Len() == 0 {
		fmt.Printf("baseline: no entries in %s\n", baselinePath)
		return 0
	}

	fmt.Printf("baseline: %d entries (%d expired) — %s\n", bl.Len(), bl.ExpiredCount(), baselinePath)

	// Show per-severity counts.
	counts := make(map[string]int)
	for _, e := range bl.Entries {
		counts[string(e.Severity)]++
	}
	for sev, count := range counts {
		fmt.Printf("  %s: %d\n", sev, count)
	}

	return 0
}

