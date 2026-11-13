package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// defaultReportDir is where `nox scan` writes its reports when neither
// --output nor output.directory names a place.
//
// It used to be the working directory, which put five untracked files into the
// repository being scanned, one `git add .` from being committed. .nox/ is
// where nox keeps a project's files already, but the ones there now
// (baseline.json, mcp-pins.json, mcp-baseline.json) are meant to be
// committed, so the reports get a directory of their own that ignores itself:
// ensureReportDir writes a .gitignore into it, the way pytest and ruff keep
// their caches out of git without touching the project's .gitignore.
var defaultReportDir = filepath.Join(".nox", "reports")

// reportDirGitignore ignores everything in the report directory, itself
// included, so git never lists it whatever the project's own .gitignore says.
const reportDirGitignore = "# Written by nox: scan reports are regenerated on every run.\n*\n"

// ensureReportDir creates dir. When dir is the default report directory it
// also writes the .gitignore that keeps the reports out of git; a directory
// the operator named is theirs, and nothing is added to it.
func ensureReportDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if filepath.Clean(dir) != defaultReportDir {
		return nil
	}
	ignore := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(ignore); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.WriteFile(ignore, []byte(reportDirGitignore), 0o644); err != nil { //nolint:gosec // a .gitignore, not a secret
		return fmt.Errorf("writing %s: %w", ignore, err)
	}
	return nil
}

// scanReportPath is where a command looks for a report a scan of root
// wrote, when it was not told: root/.nox/reports/<name>, or root/<name> for a
// report written before reports moved there. When neither exists it returns
// the new location, so an error names where `nox scan` will put it.
func scanReportPath(root, name string) string {
	current := filepath.Join(root, defaultReportDir, name)
	if fileExists(current) {
		return current
	}
	if legacy := filepath.Join(root, name); fileExists(legacy) {
		return legacy
	}
	return current
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
