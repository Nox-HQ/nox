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
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifest), 0o600); err != nil {
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
	for _, want := range []string{"dependencies (2 packages)", "No lockfile is committed beside a package.json", "commit a lockfile"} {
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
