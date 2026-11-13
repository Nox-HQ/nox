package core

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// #830: a plugin walks the workspace itself, so the files the core walk leaves
// out because .gitignore covers them came back as plugin findings. On tokenops,
// nox/triage-agent reported 475 findings from an agent worktree under the
// gitignored .claude/ — every one a duplicate of the real tree, under a random
// directory name no waiver can stay ahead of. scan.exclude already bound
// plugins; .gitignore did not, which is why excluding .claude/ was the
// workaround. Plugin findings now answer to the walker's own ignore decision.
func TestRunScan_PluginFindingsHonourGitignore(t *testing.T) {
	dir := initGitRepo(t, map[string]string{
		".gitignore":     ".claude/\nbuild/\nmobile/\n",
		"sub/.gitignore": "gen.go\n",
		"cli/main.go":    "package main\n",
	})
	// A linked worktree under the ignored directory, as Claude Code makes one.
	wt := filepath.Join(dir, ".claude", "worktrees", "agent-acfa94ceae47830a4")
	if err := os.MkdirAll(filepath.Join(wt, "internal"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitdir := "gitdir: " + filepath.Join(dir, ".git", "worktrees", "agent-acfa94ceae47830a4") + "\n"
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte(gitdir), 0o644); err != nil {
		t.Fatal(err)
	}
	// git never ignores a tracked file: mobile/ is ignored, but this file was
	// committed into it with `git add -f`, so the core walk scans it.
	tracked := filepath.Join(dir, "mobile", "app.go")
	if err := os.MkdirAll(filepath.Dir(tracked), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tracked, []byte("package mobile\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	add := exec.Command("git", "add", "-f", "mobile/app.go")
	add.Dir = dir
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("git add -f: %v\n%s", err, out)
	}
	writeNoxConfigRequiring(t, dir, "nox/triage-agent")

	setHook(t, func(_ context.Context, target string, _ []string) (*PluginScanOutput, error) {
		mk := func(rule, path string) findings.Finding {
			return findings.NewFinding(rule, findings.SeverityHigh, findings.ConfidenceHigh,
				findings.Location{FilePath: filepath.Join(target, path), StartLine: 1, EndLine: 1},
				"plugin finding")
		}
		return &PluginScanOutput{Findings: []findings.Finding{
			mk("TRIAGE-001", ".claude/worktrees/agent-acfa94ceae47830a4/internal/a.go"),
			mk("TRIAGE-002", "build/bundle.js"),
			mk("TRIAGE-003", "sub/gen.go"),
			mk("TRIAGE-004", "mobile/app.go"),
			mk("TRIAGE-005", "cli/main.go"),
		}}, nil
	})

	result, err := RunScan(dir)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	byRule := map[string]bool{}
	for _, f := range result.Findings.ActiveFindings() {
		byRule[f.RuleID] = true
	}
	for rule, why := range map[string]string{
		"TRIAGE-001": "a linked worktree under the gitignored .claude/",
		"TRIAGE-002": "the gitignored build/",
		"TRIAGE-003": "a file a nested .gitignore covers",
	} {
		if byRule[rule] {
			t.Errorf("plugin finding in %s was merged; .gitignore must bind plugins as it binds the core walk", why)
		}
	}
	if !byRule["TRIAGE-004"] {
		t.Error("plugin finding on a tracked file in an ignored directory was dropped; git never ignores a tracked file")
	}
	if !byRule["TRIAGE-005"] {
		t.Error("plugin finding on ordinary source was dropped")
	}
}
