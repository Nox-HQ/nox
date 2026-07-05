package provenance

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

func TestClassifyNPMSpec(t *testing.T) {
	cases := []struct {
		spec string
		want string
	}{
		{"^4.18.2", ""},
		{"1.2.3", ""},
		{"latest", ""},
		{"*", ""},
		{"npm:@scope/pkg@1.0.0", ""},
		{"file:../local", ""},
		{"workspace:*", ""},
		{"git+https://github.com/o/r.git#0123456789abcdef0123456789abcdef01234567", "PROV-001"},
		{"git+https://github.com/o/r.git#main", "PROV-002"},
		{"git+ssh://git@github.com/o/r.git", "PROV-002"},
		{"github:owner/repo#v1.2.3", "PROV-002"},
		{"owner/repo#abcdef1", "PROV-001"},
		{"owner/repo", "PROV-002"},
		{"https://example.com/pkg.tgz", "PROV-001"},
	}
	for _, c := range cases {
		got, _ := classifyNPMSpec(c.spec)
		if got != c.want {
			t.Errorf("classifyNPMSpec(%q) = %q, want %q", c.spec, got, c.want)
		}
	}
}

func scanFile(t *testing.T, name, body string) []string {
	t.Helper()
	dir := t.TempDir()
	abs := filepath.Join(dir, name)
	if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	art := discovery.Artifact{Path: name, AbsPath: abs, Type: discovery.Lockfile}
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{art})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	items := fs.Findings()
	for i := range items {
		ids = append(ids, items[i].RuleID)
	}
	return ids
}

func has(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestPackageJSONProvenance(t *testing.T) {
	body := `{
		"dependencies": {
			"express": "^4.18.2",
			"internal-lib": "git+https://github.com/acme/internal.git#main",
			"pinned-fork": "git+https://github.com/acme/fork.git#0123456789abcdef0123456789abcdef01234567",
			"tarball": "https://cdn.example.com/pkg-1.0.0.tgz"
		}
	}`
	ids := scanFile(t, "package.json", body)
	if !has(ids, "PROV-002") {
		t.Errorf("expected PROV-002 for mutable git ref; got %v", ids)
	}
	if !has(ids, "PROV-001") {
		t.Errorf("expected PROV-001 for pinned git + tarball; got %v", ids)
	}
	// express (registry) must not raise anything.
	if len(ids) != 3 {
		t.Errorf("expected exactly 3 findings (not express), got %d: %v", len(ids), ids)
	}
}

func TestRequirementsProvenance(t *testing.T) {
	body := "flask==2.0.1\n" +
		"requests>=2.0\n" +
		"-e git+https://github.com/acme/tool.git@main#egg=tool\n" +
		"git+https://github.com/acme/lib.git@0123456789abcdef0123456789abcdef01234567#egg=lib\n" +
		"https://example.com/wheels/foo-1.0-py3-none-any.whl\n" +
		"https://example.com/wheels/bar-1.0.whl#sha256=deadbeef\n"
	ids := scanFile(t, "requirements.txt", body)
	if !has(ids, "PROV-002") {
		t.Errorf("expected PROV-002 for git @main; got %v", ids)
	}
	if !has(ids, "PROV-001") {
		t.Errorf("expected PROV-001 for git @sha and plain wheel URL; got %v", ids)
	}
	// flask/requests (registry, versioned) and the #sha256 wheel must not fire.
	// Expected: git@main (PROV-002), git@sha (PROV-001), plain wheel (PROV-001) = 3.
	if len(ids) != 3 {
		t.Errorf("expected exactly 3 findings, got %d: %v", len(ids), ids)
	}
}
