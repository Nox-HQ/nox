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

func TestAnalyzerInterproceduralCommandInjection(t *testing.T) {
	// Cross-function: the sink lives in a helper, the tainted value is produced in
	// the handler and handed to the helper. The finding must fire and its metadata
	// must record the interprocedural path through the helper.
	dir := t.TempDir()
	art := writeArtifact(t, dir, "app.py", `def run(c):
    os.system(c)

def handler():
    cmd = request.args.get("x")
    run(cmd)
`)
	a := NewAnalyzer()
	fs, err := a.ScanArtifacts(context.Background(), []discovery.Artifact{art})
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	items := fs.Findings()
	if len(items) != 1 || items[0].RuleID != "TAINT-002" {
		t.Fatalf("want one TAINT-002 finding, got %+v", items)
	}
	f := items[0]
	if f.Metadata["interprocedural"] != "true" {
		t.Errorf("interprocedural metadata = %q, want true", f.Metadata["interprocedural"])
	}
	if f.Metadata["via"] != "run" {
		t.Errorf("via metadata = %q, want run", f.Metadata["via"])
	}
	// The finding is located at the call site (line 6, `run(cmd)`) — the
	// actionable line in the caller where untrusted data is handed to the helper.
	// The message and `via` metadata name the helper whose body holds the sink.
	if f.Location.StartLine != 6 {
		t.Errorf("sink line = %d, want 6 (the run(cmd) call site)", f.Location.StartLine)
	}
}

func TestAnalyzerInterproceduralSanitizedNoFinding(t *testing.T) {
	// The helper sanitizes its argument before the sink: no finding.
	dir := t.TempDir()
	art := writeArtifact(t, dir, "app.py", `def run(c):
    os.system(shlex.quote(c))

def handler():
    cmd = request.args.get("x")
    run(cmd)
`)
	if ids := scan(t, art); len(ids) != 0 {
		t.Fatalf("want no findings (sanitized in helper), got %v", ids)
	}
}

// scanFindings runs the analyzer and returns the full findings for metadata
// assertions (scan() projects to rule IDs only).
func scanFindings(t *testing.T, arts ...discovery.Artifact) []findingRec {
	t.Helper()
	a := NewAnalyzer()
	fs, err := a.ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatalf("ScanArtifacts: %v", err)
	}
	items := fs.Findings()
	out := make([]findingRec, 0, len(items))
	for i := range items {
		out = append(out, findingRec{ruleID: items[i].RuleID, meta: items[i].Metadata})
	}
	return out
}

type findingRec struct {
	ruleID string
	meta   map[string]string
}

// TestAnalyzerRoleAwarePromptInjection is the end-to-end proof at the analyzer
// boundary: the system-role prompt injection fires TAINT-AI-001 and carries the
// auditable sink_role=system metadata, while the user-role-behind-static-system
// pattern produces no finding at all.
func TestAnalyzerRoleAwarePromptInjection(t *testing.T) {
	dir := t.TempDir()
	sys := writeArtifact(t, dir, "sys.py", `def personalize():
    persona = request.args.get("persona")
    client.chat.completions.create(messages=[{"role": "system", "content": persona}, {"role": "user", "content": "hi"}])
`)
	recs := scanFindings(t, sys)
	var got *findingRec
	for i := range recs {
		if recs[i].ruleID == "TAINT-AI-001" {
			got = &recs[i]
		}
	}
	if got == nil {
		t.Fatalf("system-role injection did not fire TAINT-AI-001; got %v", recs)
	}
	if got.meta["sink_role"] != "system" {
		t.Errorf("sink_role = %q, want system", got.meta["sink_role"])
	}

	dir2 := t.TempDir()
	safe := writeArtifact(t, dir2, "safe.py", `def chat():
    user_q = request.args.get("q")
    client.chat.completions.create(messages=[{"role": "system", "content": "Answer concisely."}, {"role": "user", "content": user_q}])
`)
	if ids := scan(t, safe); len(ids) != 0 {
		t.Fatalf("user-role-behind-static-system must be clean of TAINT-AI-001, got %v", ids)
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
