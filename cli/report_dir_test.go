package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// `nox scan .` wrote findings.json, results.sarif, the SBOMs and the AI
// inventory into the working directory: five untracked files in the
// repository being scanned, one `git add .` from being committed. Reports now
// go to .nox/reports/, which nox creates with a .gitignore of its own, so git
// never offers them. --output and output.directory still put them anywhere.
func TestScanWritesReportsWhereGitIgnoresThem(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	t.Chdir(dir)
	gitInit := exec.Command("git", "init", "-q", ".")
	if out, err := gitInit.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	if err := os.WriteFile("main.go", []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if code := run([]string{"scan", ".", "--quiet", "--offline", "--format", "all"}); code != 0 && code != 1 {
		t.Fatalf("scan exited %d", code)
	}

	for _, name := range []string{"findings.json", "results.sarif", "sbom.cdx.json", "sbom.spdx.json", "ai.inventory.json"} {
		if _, err := os.Stat(name); err == nil {
			t.Errorf("%s was written into the working tree", name)
		}
	}
	if _, err := os.Stat(filepath.Join(".nox", "reports", "findings.json")); err != nil {
		t.Fatalf("findings.json is not under .nox/reports: %v", err)
	}

	status := exec.Command("git", "status", "--porcelain", "--untracked-files=all")
	out, err := status.CombinedOutput()
	if err != nil {
		t.Fatalf("git status: %v\n%s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.Contains(line, ".nox/") {
			t.Errorf("git offers a report to commit: %q", line)
		}
	}
}

// The commands that read a scan's findings.json default to where `nox scan`
// now writes it, and still find one a scan wrote before this change.
func TestScanReportPath(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  string
	}{
		{"nothing yet: names the new location", nil, filepath.Join(".nox", "reports", "findings.json")},
		{"the new location", []string{filepath.Join(".nox", "reports", "findings.json")}, filepath.Join(".nox", "reports", "findings.json")},
		{"a report from before", []string{"findings.json"}, "findings.json"},
		{"both: the new one wins", []string{"findings.json", filepath.Join(".nox", "reports", "findings.json")}, filepath.Join(".nox", "reports", "findings.json")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, f := range tc.files {
				p := filepath.Join(root, f)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := scanReportPath(root, "findings.json"); got != filepath.Join(root, tc.want) {
				t.Errorf("scanReportPath = %q, want %q", got, filepath.Join(root, tc.want))
			}
		})
	}
}
