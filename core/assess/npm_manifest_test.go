package assess

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
)

func assessProject(t *testing.T, manifest string) string {
	t.Helper()
	return assessFile(t, "package.json", manifest)
}

func assessFile(t *testing.T, name, manifest string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := nox.RunScanContext(context.Background(), dir, nox.ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	in := FromScan(res, res.Findings.ActiveFindings(), dir, "", true)
	var b strings.Builder
	if err := Render(&b, Build(in), RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// A manifest that declares dependencies must never read as "none found", and a
// missing lockfile is named with the fix.
func TestAssessment_ManifestWithoutLockfileIsNotNoneFound(t *testing.T) {
	out := assessProject(t, `{"dependencies":{"axios":"0.21.1","express":"4.17.1"}}`)
	if strings.Contains(out, "none found") {
		t.Errorf("assessment says \"none found\" for a manifest declaring dependencies:\n%s", out)
	}
	for _, want := range []string{"dependencies (2 packages)", "manifests were read without a lockfile or could not be read", "commit a lockfile"} {
		if !strings.Contains(out, want) {
			t.Errorf("assessment lacks %q:\n%s", want, out)
		}
	}
}

// Declared but unresolvable (workspace/git specs only): still not "none found".
func TestAssessment_UnresolvableManifestIsNotNoneFound(t *testing.T) {
	out := assessProject(t, `{"dependencies":{"internal":"workspace:*","forked":"github:a/b"}}`)
	if strings.Contains(out, "none found") {
		t.Errorf("assessment says \"none found\":\n%s", out)
	}
	if !strings.Contains(out, "declared, but none could be resolved") || !strings.Contains(out, "NOT checked") {
		t.Errorf("assessment does not say the dependencies were declared and unchecked:\n%s", out)
	}
}

// And a project that really has no dependencies still says so.
func TestAssessment_NoManifestDependenciesStillNoneFound(t *testing.T) {
	out := assessProject(t, `{"name":"empty"}`)
	if !strings.Contains(out, "dependencies (none found)") {
		t.Errorf("a manifest with no dependencies should still read none found:\n%s", out)
	}
}

// The reproduced false all-clear: a project whose only dependency declaration is
// a manifest nox did not read told the reader "dependencies (none found)" and
// "No issues found in what was checked".
func TestAssessment_UnreadManifestIsNeverAnAllClear(t *testing.T) {
	cases := map[string]string{
		"Cargo.toml":     "[dependencies]\nsmallvec = \"=1.6.0\"\n",
		"pyproject.toml": "[project]\ndependencies = [\"django==2.2.0\"]\n",
		"Package.swift":  "// swift-tools-version:5.5\n",
		"mix.exs":        "defmodule X.MixProject do\nend\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			out := assessFile(t, name, body)
			for _, banned := range []string{"none found", "No issues found in what was checked"} {
				if strings.Contains(out, banned) {
					t.Errorf("%s: assessment says %q although %s was not fully checked:\n%s", name, banned, name, out)
				}
			}
			if !strings.Contains(out, name) && !strings.Contains(out, "NOT") {
				t.Errorf("%s: assessment does not say what was not checked:\n%s", name, out)
			}
		})
	}
}
