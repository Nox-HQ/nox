package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/change"
	"github.com/nox-hq/nox/core/diff"
)

// runDiff reports what a range of commits changed in the project's security
// state: it scans the base and head trees and compares them (core/diff). Exit 1
// means the change made findings worse (something new, or a severity raised);
// resolved items, leads and agent-capability changes are reported but do not
// fail a build, because they are hints a person weighs.
func runDiff(args []string) int { return runDiffWith(args, false) }

// runDiffWith is runDiff with the global --verbose, which lists every line.
func runDiffWith(args []string, all bool) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	var (
		base      string
		head      string
		rulesPath string
		jsonFlag  bool
		offline   bool
		noOSV     bool
	)
	fs.StringVar(&base, "base", "main", "base ref for comparison")
	fs.StringVar(&head, "head", "HEAD", "head ref for comparison")
	fs.StringVar(&rulesPath, "rules", "", "path to custom rules YAML file or directory")
	fs.BoolVar(&jsonFlag, "json", false, "output as JSON")
	fs.BoolVar(&offline, "offline", false, "make no network calls in either scan (no dependency advisory lookups)")
	fs.BoolVar(&noOSV, "no-osv", false, "disable OSV.dev vulnerability lookups in both scans")
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	result, err := diff.Run(target, diff.Options{
		Base:       base,
		Head:       head,
		RulesPath:  rulesPath,
		Offline:    offline,
		DisableOSV: noOSV,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	if len(result.ChangedFiles) == 0 {
		if jsonFlag {
			return printDiffJSON(result)
		}
		fmt.Println("diff: no changed files")
		return 0
	}

	if jsonFlag {
		if code := printDiffJSON(result); code != 0 {
			return code
		}
	} else {
		fmt.Printf("diff: %d changed file(s) (%s...%s)\n", len(result.ChangedFiles), result.Base, result.Head)
		limit := change.DefaultLimit
		if all {
			limit = 0
		}
		if err := change.Render(os.Stdout, result.Change, limit); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
	}

	if result.Change.Regressions() > 0 {
		return 1
	}
	return 0
}

func printDiffJSON(result *diff.Result) int {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshalling: %v\n", err)
		return 2
	}
	fmt.Println(string(data))
	return 0
}
