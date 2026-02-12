package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/nox-hq/nox/core/annotate"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/git"
	"github.com/nox-hq/nox/core/report"
)

func runAnnotate(args []string) int {
	fs := flag.NewFlagSet("annotate", flag.ContinueOnError)
	var (
		inputPath string
		prNumber  string
		repo      string
	)
	fs.StringVar(&inputPath, "input", "findings.json", "path to findings.json")
	fs.StringVar(&prNumber, "pr", "", "PR number (auto-detected from GITHUB_REF)")
	fs.StringVar(&repo, "repo", "", "repository owner/name (auto-detected from GITHUB_REPOSITORY)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Auto-detect PR number from GITHUB_REF.
	if prNumber == "" {
		ref := os.Getenv("GITHUB_REF")
		if strings.HasPrefix(ref, "refs/pull/") {
			parts := strings.Split(ref, "/")
			if len(parts) >= 3 {
				prNumber = parts[2]
			}
		}
	}

	// Auto-detect repo from GITHUB_REPOSITORY.
	if repo == "" {
		repo = os.Getenv("GITHUB_REPOSITORY")
	}

	if prNumber == "" {
		fmt.Fprintln(os.Stderr, "error: could not determine PR number (use --pr or set GITHUB_REF)")
		return 2
	}
	if repo == "" {
		fmt.Fprintln(os.Stderr, "error: could not determine repository (use --repo or set GITHUB_REPOSITORY)")
		return 2
	}

	// Read findings.
	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", inputPath, err)
		return 2
	}

	var jsonReport report.JSONReport
	if err := json.Unmarshal(data, &jsonReport); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", inputPath, err)
		return 2
	}

	ff := jsonReport.Findings
	if len(ff) == 0 {
		fmt.Println("annotate: no findings to annotate")
		return 0
	}

	// Filter to changed files if possible.
	changedSet := getChangedFilesSet()
	if changedSet != nil {
		var filtered []findings.Finding
		for _, f := range ff {
			if _, ok := changedSet[f.Location.FilePath]; ok {
				filtered = append(filtered, f)
			}
		}
		ff = filtered
	}

	if len(ff) == 0 {
		fmt.Println("annotate: no findings in changed files")
		return 0
	}

	// Build payload using core/annotate.
	payload := annotate.BuildReviewPayload(ff)
	if payload == nil {
		fmt.Println("annotate: no findings to annotate")
		return 0
	}

	// Post review comments via gh CLI.
	if err := postReviewComments(repo, prNumber, payload); err != nil {
		fmt.Fprintf(os.Stderr, "error: posting annotations: %v\n", err)
		return 2
	}

	fmt.Printf("annotate: posted %d finding(s) to %s#%s\n", len(ff), repo, prNumber)
	return 0
}

func getChangedFilesSet() map[string]struct{} {
	if !git.IsGitRepo(".") {
		return nil
	}
	repoRoot, err := git.RepoRoot(".")
	if err != nil {
		return nil
	}

	// Try to get changed files from PR base.
	base := os.Getenv("GITHUB_BASE_REF")
	if base == "" {
		base = "main"
	}

	changed, err := git.ChangedFiles(repoRoot, "origin/"+base, "HEAD")
	if err != nil {
		return nil
	}

	set := make(map[string]struct{}, len(changed))
	for _, f := range changed {
		set[f] = struct{}{}
	}
	return set
}

func postReviewComments(repo, prNumber string, payload *annotate.ReviewPayload) error {
	payloadData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling payload: %w", err)
	}

	endpoint := fmt.Sprintf("repos/%s/pulls/%s/reviews", repo, prNumber)
	cmd := exec.Command("gh", "api", endpoint, "--method", "POST", "--input", "-")
	cmd.Stdin = strings.NewReader(string(payloadData))
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gh api: %w", err)
	}

	return nil
}
