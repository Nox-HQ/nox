package taintflow

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// writeArtifact writes content to a temp file and returns the discovery.Artifact
// pointing at it, typed as Source.
func writeArtifact(t *testing.T, dir, name, content string) discovery.Artifact {
	t.Helper()
	abs := filepath.Join(dir, name)
	if err := os.WriteFile(abs, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return discovery.Artifact{Path: name, AbsPath: abs, Type: discovery.Source}
}

func scan(t *testing.T, arts ...discovery.Artifact) []string {
	t.Helper()
	a := NewAnalyzer()
	fs, err := a.ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	var ids []string
	items := fs.Findings()
	for i := range items {
		ids = append(ids, items[i].RuleID)
	}
	return ids
}

func TestAnalyzerTruePositiveSQLi(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "app.py", `def handler():
    q = request.args.get("id")
    cursor.execute("SELECT * FROM t WHERE id = " + q)
`)
	ids := scan(t, art)
	if len(ids) != 1 || ids[0] != "TAINT-001" {
		t.Fatalf("want [TAINT-001], got %v", ids)
	}
}

func TestAnalyzerTruePositiveCommandInjection(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "app.py", `def handler():
    cmd = flask.request.args.get("c")
    os.system(cmd)
`)
	ids := scan(t, art)
	if len(ids) != 1 || ids[0] != "TAINT-002" {
		t.Fatalf("want [TAINT-002], got %v", ids)
	}
}

func TestAnalyzerSanitizedNoFinding(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "app.py", `def handler():
    user = request.args.get("c")
    os.system(shlex.quote(user))
`)
	if ids := scan(t, art); len(ids) != 0 {
		t.Fatalf("want no findings (sanitized), got %v", ids)
	}
}

func TestAnalyzerNoSourceNoFinding(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "app.py", `def handler():
    os.system("ls -la")
`)
	if ids := scan(t, art); len(ids) != 0 {
		t.Fatalf("want no findings (no source), got %v", ids)
	}
}

func TestAnalyzerFindingMetadataAndLocation(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "app.py", `def handler():
    q = request.args.get("id")
    cursor.execute("SELECT * FROM t WHERE id = " + q)
`)
	a := NewAnalyzer()
	fs, err := a.ScanArtifacts(context.Background(), []discovery.Artifact{art})
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	items := fs.Findings()
	if len(items) != 1 {
		t.Fatalf("want 1 finding, got %d", len(items))
	}
	f := items[0]
	if f.Location.FilePath != "app.py" || f.Location.StartLine != 3 {
		t.Errorf("location = %s:%d, want app.py:3", f.Location.FilePath, f.Location.StartLine)
	}
	if f.Metadata["cwe"] != "CWE-89" {
		t.Errorf("cwe metadata = %q, want CWE-89", f.Metadata["cwe"])
	}
	if f.Metadata["vuln_class"] != "sql_injection" {
		t.Errorf("vuln_class metadata = %q, want sql_injection", f.Metadata["vuln_class"])
	}
	if f.Metadata["source_kind"] == "" || f.Metadata["sink"] == "" {
		t.Errorf("missing source/sink metadata: %+v", f.Metadata)
	}
}

func TestAnalyzerSkipsNonSource(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "app.py", `def handler():
    q = request.args.get("id")
    os.system(q)
`)
	art.Type = discovery.Config // not a Source artifact
	if ids := scan(t, art); len(ids) != 0 {
		t.Fatalf("want no findings for non-Source artifact, got %v", ids)
	}
}

func TestAnalyzerDeterministicAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	a1 := writeArtifact(t, dir, "b.py", `def h():
    q = request.args.get("id")
    os.system(q)
`)
	a2 := writeArtifact(t, dir, "a.py", `def h():
    q = request.args.get("id")
    eval(q)
`)
	first := scan(t, a1, a2)
	for i := 0; i < 5; i++ {
		if got := scan(t, a1, a2); len(got) != len(first) {
			t.Fatalf("nondeterministic finding count")
		}
	}
}

func TestAnalyzerRules(t *testing.T) {
	rs := NewAnalyzer().Rules()
	want := map[string]bool{"TAINT-001": false, "TAINT-002": false, "TAINT-005": false}
	for _, r := range rs.Rules() {
		if _, ok := want[r.ID]; ok {
			want[r.ID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("rule %s not registered", id)
		}
	}
}
