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

// TestStructuralGoXSSToResponse covers the three reflected-XSS-to-response shapes:
// fmt.Fprintf of an interpolated tainted value, w.Write of a []byte HTML concat,
// and the template.HTML auto-escape bypass. Each must fire TAINT-003 (xss).
func TestStructuralGoXSSToResponse(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "fmt.Fprintf interpolates tainted value into HTML",
			src: `package web
func greet(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<div>Hello, %s</div>", name)
}`,
		},
		{
			name: "w.Write of []byte HTML concat",
			src: `package web
func greet(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	_, _ = w.Write([]byte("<b>" + user + "</b>"))
}`,
		},
		{
			name: "io.WriteString of tainted value",
			src: `package web
func greet(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	_, _ = io.WriteString(w, user)
}`,
		},
		{
			name: "template.HTML auto-escape bypass",
			src: `package web
func greet(w http.ResponseWriter, r *http.Request) {
	comment := r.URL.Query().Get("comment")
	t := template.Must(template.New("c").Parse("<p>{{.}}</p>"))
	_ = t.Execute(w, template.HTML(comment))
}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzeGoFile(t, tt.src)
			found := false
			for _, id := range ids {
				if id == "TAINT-003" {
					found = true
				}
			}
			if !found {
				t.Errorf("xss-to-response: got %v, want TAINT-003", ids)
			}
		})
	}
}

// TestStructuralGoSafeAutoescapeStaysClean guards clean_html_autoescape.go: safe
// html/template rendering — user data passed as a plain struct field to
// Execute, which contextually auto-escapes — must fire NOTHING. Execute is not
// modeled as a sink; only the template.HTML bypass and raw writes are.
func TestStructuralGoSafeAutoescapeStaysClean(t *testing.T) {
	src := `package web
var page = template.Must(template.New("page").Parse("<h1>{{.Name}}</h1>"))
func render(w http.ResponseWriter, r *http.Request) {
	data := struct{ Name string }{Name: r.URL.Query().Get("name")}
	_ = page.Execute(w, data)
}`
	ids := analyzeGoFile(t, src)
	if len(ids) != 0 {
		t.Errorf("safe auto-escape: want zero findings, got %v", ids)
	}
}

// TestStructuralGoContainerTaint covers container-level taint: a request value
// stashed into a map value (m["c"]=user) then read back at the command sink
// (m["c"]) must fire TAINT-002. The extractor attributes the index assignment to
// the base m, so the whole container is tainted and the later read of m is
// dangerous.
func TestStructuralGoContainerTaint(t *testing.T) {
	src := `package j
func runMap(r *Req) {
	user := r.FormValue("c")
	m := map[string]string{}
	m["c"] = user
	out, _ := exec.Command("sh", "-c", m["c"]).Output()
	_ = out
}`
	ids := analyzeGoFile(t, src)
	found := false
	for _, id := range ids {
		if id == "TAINT-002" {
			found = true
		}
	}
	if !found {
		t.Errorf("container taint: got %v, want TAINT-002 (map value flows to sink)", ids)
	}
}

// TestStructuralGoSanitizedFieldStaysClean guards clean_field_safe.go: a request
// value sanitized into a local (strconv.Atoi) BEFORE being stored in a struct
// field, then read at the sink, must fire nothing — the sanitized local carries
// the cleared class into the field-assigned base, so the container-level base
// attribution does not resurrect the taint.
func TestStructuralGoSanitizedFieldStaysClean(t *testing.T) {
	src := `package j
func build(r *Req) {
	raw := r.FormValue("count")
	count := strconv.Atoi(raw)
	var t Ticket
	t.Count = count
	out, _ := exec.Command("gen", "--count", t.Count).Output()
	_ = out
}`
	ids := analyzeGoFile(t, src)
	if len(ids) != 0 {
		t.Errorf("sanitized field: want zero findings, got %v", ids)
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
