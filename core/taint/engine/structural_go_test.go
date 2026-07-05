package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzeGoFile runs the full same-file pipeline (extraction + interprocedural
// AnalyzeFile) over Go source, mirroring how taintflow drives the engine.
func analyzeGoFile(t *testing.T, src string) []string {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t.go", lexctx.LangGo, []byte(src))
	flows := eng.AnalyzeFile(units)
	return ruleIDs(flows)
}

func TestStructuralGoTruePositives(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		wantID string
	}{
		{
			name: "command injection via exec.Command",
			src: `package h
func handle(r *Req) {
	name := r.URL.Query().Get("report")
	exec.Command("sh", "-c", "gen "+name).Output()
}`,
			wantID: "TAINT-002",
		},
		{
			name: "sql injection via db.Query concat",
			src: `package s
func lookup(db *DB, r *Req) {
	id := r.URL.Query().Get("id")
	_ = db.Query("SELECT * FROM t WHERE id = '" + id + "'")
}`,
			wantID: "TAINT-001",
		},
		{
			name: "path traversal via os.ReadFile",
			src: `package f
func serve(r *Req) {
	name := r.URL.Query().Get("file")
	_, _ = os.ReadFile(filepath.Join("/srv", name))
}`,
			wantID: "TAINT-004",
		},
		{
			name: "ssrf via http.Get",
			src: `package p
func fetch(r *Req) {
	target := r.URL.Query().Get("url")
	_, _ = http.Get(target)
}`,
			wantID: "TAINT-006",
		},
		{
			name: "unsafe deserialization via gob",
			src: `package s
func restore(r *Req) {
	var env E
	if err := gob.NewDecoder(r.Body).Decode(&env); err != nil {
		_ = err
	}
}`,
			wantID: "TAINT-005",
		},
		{
			name: "ssti via text/template Parse",
			src: `package r
func greet(r *Req) {
	src := r.URL.Query().Get("tmpl")
	_, _ = template.New("greeting").Parse(src)
}`,
			wantID: "TAINT-003",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzeGoFile(t, tt.src)
			found := false
			for _, id := range ids {
				if id == tt.wantID {
					found = true
				}
			}
			if !found {
				t.Errorf("got rule IDs %v, want to include %s", ids, tt.wantID)
			}
		})
	}
}

// TestStructuralGoCleanStaysClean asserts the precision guardrails fire nothing:
// parameterized queries, arg-vector exec, and sanitized paths.
func TestStructuralGoCleanStaysClean(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "parameterized query is safe",
			src: `package s
func lookup(db *DB, id string) {
	_ = db.Query("SELECT name FROM users WHERE id = $1", id)
}`,
		},
		{
			name: "arg-vector exec is safe",
			src: `package s
func listDir(dir string) {
	_, _ = exec.Command("ls", "-la", "--", dir).Output()
}`,
		},
		{
			name: "filepath.Clean sanitizes path traversal",
			src: `package f
func serve(r *Req) {
	name := r.URL.Query().Get("file")
	clean := filepath.Base(name)
	_, _ = os.ReadFile(filepath.Join("/srv", clean))
}`,
		},
		{
			name: "no source means no flow",
			src: `package s
func run(dir string) {
	_, _ = exec.Command("sh", "-c", "gen "+dir).Output()
}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzeGoFile(t, tt.src)
			if len(ids) != 0 {
				t.Errorf("want zero findings, got %v", ids)
			}
		})
	}
}

// TestStructuralGoInterprocSameFile covers a source in a handler flowing through a
// locally-defined helper to a sink (the same-file interprocedural summary path).
func TestStructuralGoInterprocSameFile(t *testing.T) {
	src := `package h
func run(cmd string) {
	exec.Command("sh", "-c", cmd).Output()
}
func handle(r *Req) {
	name := r.URL.Query().Get("x")
	run(name)
}`
	ids := analyzeGoFile(t, src)
	found := false
	for _, id := range ids {
		if id == "TAINT-002" {
			found = true
		}
	}
	if !found {
		t.Errorf("interproc: got %v, want TAINT-002 (source flows through run helper)", ids)
	}
}
