// Package diff provides security diff scanning between git refs.
// It identifies findings in changed files, allowing both CLI and MCP
// to share the same business logic.
package diff

import (
	"fmt"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/git"
)

// Options configures a diff scan.
type Options struct {
	Base      string // base git ref (default: "main")
	Head      string // head git ref (default: "HEAD")
	RulesPath string // optional custom rules path
}

// Finding is a finding scoped to a changed file.
type Finding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// Result holds the output of a diff scan.
type Result struct {
	Findings     []Finding `json:"findings"`
	ChangedFiles []string  `json:"changed_files"`
	Base         string    `json:"base"`
	Head         string    `json:"head"`
}

// Run performs a diff scan on the target directory, scanning only files
// changed between the Base and Head refs.
func Run(target string, opts Options) (*Result, error) {
	if opts.Base == "" {
		opts.Base = "main"
	}
	if opts.Head == "" {
		opts.Head = "HEAD"
	}

	if !git.IsGitRepo(target) {
		return nil, fmt.Errorf("not a git repository")
	}

	repoRoot, err := git.RepoRoot(target)
	if err != nil {
		return nil, fmt.Errorf("resolving repo root: %w", err)
	}

	changed, err := git.ChangedFiles(repoRoot, opts.Base, opts.Head)
	if err != nil {
		return nil, fmt.Errorf("getting changed files: %w", err)
	}

	result := &Result{
		ChangedFiles: changed,
		Base:         opts.Base,
		Head:         opts.Head,
	}

	if len(changed) == 0 {
		return result, nil
	}

	changedSet := make(map[string]struct{}, len(changed))
	for _, f := range changed {
		changedSet[f] = struct{}{}
	}

	scanOpts := nox.ScanOptions{
		CustomRulesPath: opts.RulesPath,
	}
	scanResult, err := nox.RunScanWithOptions(target, scanOpts)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	active := scanResult.Findings.ActiveFindings()
	for i := range active {
		if _, ok := changedSet[active[i].Location.FilePath]; ok {
			result.Findings = append(result.Findings, Finding{
				RuleID:   active[i].RuleID,
				Severity: string(active[i].Severity),
				File:     active[i].Location.FilePath,
				Line:     active[i].Location.StartLine,
				Message:  active[i].Message,
			})
		}
	}

	return result, nil
}
