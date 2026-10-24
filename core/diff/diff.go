// Package diff says what a range of commits changed in a project's security
// state. It scans the tree at the base and the tree at the head and compares
// the two with core/change, so the CLI and the MCP server share one answer.
//
// It used to filter one scan to the files that differ. That is not a delta: a
// one-line lockfile change reprinted every advisory in the file, and a change
// that fixed or introduced something outside the touched files, such as a route
// that lost its auth check or an agent that gained a tool, was invisible. Both
// trees are now scanned and compared, so the answer is "new", "resolved" and
// "got worse", whichever files carry it.
package diff

import (
	"fmt"
	"os"
	"path/filepath"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/change"
	"github.com/nox-hq/nox/core/git"
)

// Options configures a diff scan.
type Options struct {
	Base      string // base git ref (default: "main")
	Head      string // head git ref (default: "HEAD")
	RulesPath string // optional custom rules path
	// Offline makes both scans use no network, so dependency advisories are not
	// looked up. DisableOSV skips only the OSV.dev lookup.
	Offline    bool
	DisableOSV bool
}

// Finding is a new finding, in the shape this command has always returned.
type Finding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// Result holds the output of a diff scan.
type Result struct {
	// Findings are the findings the head introduced (Change.New), kept in the
	// original shape for consumers of the earlier output.
	Findings []Finding `json:"findings"`
	// ChangedFiles are the files that differ between the refs.
	ChangedFiles []string `json:"changed_files"`
	Base         string   `json:"base"`
	Head         string   `json:"head"`
	// Change is the full delta: new, resolved, regressions, agent capability
	// changes and authorization leads.
	Change change.Delta `json:"change"`
}

// Run scans the base and head trees of the repository containing target and
// compares them. Neither tree is checked out: both are read from the object
// database into temporary directories, so the user's working tree, index and
// refs are never touched and uncommitted changes are not part of either side.
//
// The base is the merge-base of Base and Head when one exists, the same
// three-dot semantics ChangedFiles uses. Comparing against the tip of a base
// branch that has moved on would report what the head lacks from the base as if
// the head had introduced it.
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
		Change:       change.Compare(change.State{Label: opts.Base}, change.State{Label: opts.Base}),
		Findings:     []Finding{},
	}
	if len(changed) == 0 {
		return result, nil
	}

	sub, err := subdir(repoRoot, target)
	if err != nil {
		return nil, err
	}

	baseRef := opts.Base
	var extra []string
	if mb, mbErr := git.MergeBase(repoRoot, opts.Base, opts.Head); mbErr == nil && mb != "" {
		baseRef = mb
	} else {
		extra = append(extra, "No common ancestor of "+opts.Base+" and "+opts.Head+" was found; compared against the tip of "+opts.Base+".")
	}

	before, err := scanRef(repoRoot, baseRef, sub, opts, opts.Base)
	if err != nil {
		return nil, fmt.Errorf("scanning base %s: %w", opts.Base, err)
	}
	after, err := scanRef(repoRoot, opts.Head, sub, opts, opts.Head)
	if err != nil {
		return nil, fmt.Errorf("scanning head %s: %w", opts.Head, err)
	}

	result.Change = change.Compare(before, after)
	result.Change.Caveats = append(result.Change.Caveats, extra...)
	for _, it := range result.Change.New {
		result.Findings = append(result.Findings, Finding{
			RuleID: it.RuleID, Severity: it.Severity, File: it.File, Line: it.Line, Message: it.Message,
		})
	}
	return result, nil
}

// subdir is target relative to the repository root, so a scan of a
// subdirectory compares the same subdirectory on both sides.
func subdir(repoRoot, target string) (string, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	// Resolve symlinks on both sides: git reports a resolved top-level, and a
	// target under a symlinked path would otherwise not be relative to it.
	if r, rerr := filepath.EvalSymlinks(abs); rerr == nil {
		abs = r
	}
	root := repoRoot
	if r, rerr := filepath.EvalSymlinks(repoRoot); rerr == nil {
		root = r
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || !filepath.IsLocal(rel) && rel != "." {
		return "", fmt.Errorf("%s is not inside the repository at %s", target, repoRoot)
	}
	return rel, nil
}

// scanRef exports ref into a temporary directory, scans it, and removes it.
func scanRef(repoRoot, ref, sub string, opts Options, label string) (change.State, error) {
	tmp, err := os.MkdirTemp("", "nox-diff-*")
	if err != nil {
		return change.State{}, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	if err := git.ExportTree(repoRoot, ref, tmp); err != nil {
		return change.State{}, err
	}
	dir := filepath.Join(tmp, sub)
	if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
		// The directory did not exist at this ref: the scan of it is empty, and
		// everything in it on the other side is new.
		return change.State{Label: label, LeadsRecorded: true}, nil
	}
	res, err := nox.RunScanWithOptions(dir, nox.ScanOptions{
		CustomRulesPath: opts.RulesPath,
		Offline:         opts.Offline,
		DisableOSV:      opts.DisableOSV,
	})
	if err != nil {
		return change.State{}, fmt.Errorf("scan failed: %w", err)
	}
	return change.FromScan(res, label), nil
}
