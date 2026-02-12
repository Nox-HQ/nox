package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/diff"
)

func runDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	var (
		base      string
		head      string
		rulesPath string
		jsonFlag  bool
	)
	fs.StringVar(&base, "base", "main", "base ref for comparison")
	fs.StringVar(&head, "head", "HEAD", "head ref for comparison")
	fs.StringVar(&rulesPath, "rules", "", "path to custom rules YAML file or directory")
	fs.BoolVar(&jsonFlag, "json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	result, err := diff.Run(target, diff.Options{
		Base:      base,
		Head:      head,
		RulesPath: rulesPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	if len(result.ChangedFiles) == 0 {
		fmt.Println("diff: no changed files")
		return 0
	}

	if jsonFlag {
		data, err := json.MarshalIndent(result.Findings, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: marshalling: %v\n", err)
			return 2
		}
		fmt.Println(string(data))
	} else {
		fmt.Printf("diff: %d finding(s) in %d changed file(s) (%s...%s)\n",
			len(result.Findings), len(result.ChangedFiles), result.Base, result.Head)
		for _, f := range result.Findings {
			fmt.Printf("  [%s] %s:%d — %s (%s)\n", f.Severity, f.File, f.Line, f.Message, f.RuleID)
		}
	}

	if len(result.Findings) > 0 {
		return 1
	}
	return 0
}
