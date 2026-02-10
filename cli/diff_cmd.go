package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/git"
)

func runDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	var (
		base     string
		head     string
		jsonFlag bool
	)
	fs.StringVar(&base, "base", "main", "base ref for comparison")
	fs.StringVar(&head, "head", "HEAD", "head ref for comparison")
	fs.BoolVar(&jsonFlag, "json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	if !git.IsGitRepo(target) {
		fmt.Fprintln(os.Stderr, "error: not a git repository")
		return 2
	}

	repoRoot, err := git.RepoRoot(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	changed, err := git.ChangedFiles(repoRoot, base, head)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: getting changed files: %v\n", err)
		return 2
	}

	if len(changed) == 0 {
		fmt.Println("diff: no changed files")
		return 0
	}

	changedSet := make(map[string]struct{}, len(changed))
	for _, f := range changed {
		changedSet[f] = struct{}{}
	}

	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	// Filter findings to changed files only.
	var filtered []struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		File     string `json:"file"`
		Line     int    `json:"line"`
		Message  string `json:"message"`
	}
	for _, f := range result.Findings.ActiveFindings() {
		if _, ok := changedSet[f.Location.FilePath]; ok {
			filtered = append(filtered, struct {
				RuleID   string `json:"rule_id"`
				Severity string `json:"severity"`
				File     string `json:"file"`
				Line     int    `json:"line"`
				Message  string `json:"message"`
			}{
				RuleID:   f.RuleID,
				Severity: string(f.Severity),
				File:     f.Location.FilePath,
				Line:     f.Location.StartLine,
				Message:  f.Message,
			})
		}
	}

	if jsonFlag {
		data, err := json.MarshalIndent(filtered, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: marshalling: %v\n", err)
			return 2
		}
		fmt.Println(string(data))
	} else {
		fmt.Printf("diff: %d finding(s) in %d changed file(s) (%s...%s)\n", len(filtered), len(changed), base, head)
		for _, f := range filtered {
			fmt.Printf("  [%s] %s:%d — %s (%s)\n", f.Severity, f.File, f.Line, f.Message, f.RuleID)
		}
	}

	if len(filtered) > 0 {
		return 1
	}
	return 0
}
