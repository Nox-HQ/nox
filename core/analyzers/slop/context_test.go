package slop

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// A PR-scoped scan (--changed-since) hands the analyzer only the files the PR
// touched. The manifest that declares an import is usually not one of them:
// on PR #1082, editing safe.py's flask import reported flask as undeclared
// while requirements.txt beside it declared it. What a project declares is a
// property of the tree; which files are reported on is a property of the diff.
func TestUnchangedManifestStillDeclares(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) discovery.Artifact {
		abs := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return discovery.Artifact{Path: rel, AbsPath: abs, Type: discovery.Source}
	}
	manifest := write("app/requirements.txt", "flask\n")
	manifest.Type = discovery.Lockfile
	helper := write("helpers.py", "def h():\n    return 1\n")
	changed := write("app/safe.py", "from flask import Flask\nimport helpers\nimport flaskk_utils\n")

	fs, err := NewAnalyzer().ScanArtifactsInContext(context.Background(),
		[]discovery.Artifact{changed},
		[]discovery.Artifact{manifest, helper, changed})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs.Findings() {
		if f.RuleID == "SLOP-001" {
			got = append(got, f.Metadata["package"])
		}
	}
	if len(got) != 1 || got[0] != "flaskk_utils" {
		t.Fatalf("SLOP-001 packages = %q, want only the undeclared flaskk_utils", got)
	}
	for _, f := range fs.Findings() {
		if f.Location.FilePath != "app/safe.py" {
			t.Errorf("reported on unchanged file %s", f.Location.FilePath)
		}
	}
}
