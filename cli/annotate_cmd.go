package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
		inputPath   string
		prNumber    string
		repo        string
		summary     bool
		maxComments int
		minSeverity string
	)
	fs.StringVar(&inputPath, "input", scanReportPath(".", "findings.json"), "path to findings.json")
	fs.StringVar(&prNumber, "pr", "", "PR number (auto-detected from GITHUB_REF)")
	fs.StringVar(&repo, "repo", "", "repository owner/name (auto-detected from GITHUB_REPOSITORY)")
	fs.BoolVar(&summary, "summary", false, "also post a comment counting every finding by severity")
	fs.IntVar(&maxComments, "max-comments", 0, "post at most this many inline comments, most severe first (0: no limit)")
	fs.StringVar(&minSeverity, "min-severity", "", "post inline comments only at or above this severity")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if minSeverity != "" && !findings.Severity(minSeverity).IsValid() {
		fmt.Fprintf(os.Stderr, "error: --min-severity %q is not a severity (critical, high, medium, low, info)\n", minSeverity)
		return 2
	}
	if maxComments < 0 {
		fmt.Fprintln(os.Stderr, "error: --max-comments cannot be negative")
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

	// Read findings via the one shared loader, which reads the report nox
	// writes whatever its layout. (The Action's PR comment once parsed it
	// with sed, one line at a time, and counted zero of every severity in
	// the indented report nox emits: #1016.)
	all, err := report.LoadFindingsFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", inputPath, err)
		return 2
	}
	opts := annotate.Options{MaxComments: maxComments, MinSeverity: findings.Severity(minSeverity)}

	// Inline comments: findings in changed files, if those can be told.
	inline := all
	if changedSet := getChangedFilesSet(); changedSet != nil {
		inline = nil
		for i := range all {
			if _, ok := changedSet[all[i].Location.FilePath]; ok {
				inline = append(inline, all[i])
			}
		}
	}
	inline = annotate.Select(inline, opts)

	status, posted := 0, 0
	switch payload := annotate.BuildReviewPayload(inline); {
	case len(all) == 0:
		fmt.Println("annotate: no findings to annotate")
	case payload == nil:
		fmt.Println("annotate: no findings in changed files")
	default:
		if err := ghAPI(fmt.Sprintf("repos/%s/pulls/%s/reviews", repo, prNumber), payload); err != nil {
			fmt.Fprintf(os.Stderr, "error: posting annotations: %v\n", err)
			status = 2
		} else {
			posted = len(inline)
			fmt.Printf("annotate: posted %d finding(s) to %s#%s\n", posted, repo, prNumber)
		}
	}

	if summary {
		body := map[string]string{"body": annotate.Summary(all, posted, opts)}
		if err := ghAPI(fmt.Sprintf("repos/%s/issues/%s/comments", repo, prNumber), body); err != nil {
			fmt.Fprintf(os.Stderr, "error: posting summary: %v\n", err)
			status = 2
		} else {
			fmt.Printf("annotate: posted summary of %d finding(s) to %s#%s\n", len(all), repo, prNumber)
		}
	}
	return status
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

// ghAPI POSTs body as JSON to a GitHub API endpoint through the gh CLI,
// which authenticates from GH_TOKEN or GITHUB_TOKEN.
func ghAPI(endpoint string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshalling payload: %w", err)
	}
	cmd := exec.Command("gh", "api", endpoint, "--method", "POST", "--input", "-")
	cmd.Stdin = strings.NewReader(string(data))
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gh api: %w", err)
	}
	return nil
}
