package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractGoAssignmentAndCall covers the core shape: a short-var-decl
// assignment from a source call chain, then a bare sink call reading the tainted
// variable. It asserts the LHS name, the rendered call chains, and the reads.
func TestExtractGoAssignmentAndCall(t *testing.T) {
	src := []byte(`package h

import (
	"net/http"
	"os/exec"
)

func handle(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("report")
	exec.Command("sh", "-c", "gen "+name).Output()
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "handle")

	// Parameters preserved in order (receiver-less function: w, r).
	if len(u.params) != 2 || u.params[0] != "w" || u.params[1] != "r" {
		t.Errorf("params = %v, want [w r]", u.params)
	}

	assign := stmtWithCall(t, u, "r.URL.Query.Get")
	if assign.assigns != "name" {
		t.Errorf("assign LHS = %q, want name", assign.assigns)
	}

	sink := stmtWithCall(t, u, "exec.Command")
	if !containsStr(sink.reads, "name") {
		t.Errorf("sink reads = %v, want to include name", sink.reads)
	}
}

// TestExtractGoReturnCall covers a `return db.Query(... + id)` statement: the
// return must carry the sink call and read the tainted variable.
func TestExtractGoReturnCall(t *testing.T) {
	src := []byte(`package s

import (
	"database/sql"
	"net/http"
)

func lookup(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	id := r.URL.Query().Get("id")
	return db.Query("SELECT * FROM t WHERE id = '" + id + "'")
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "lookup")

	sink := stmtWithCall(t, u, "db.Query")
	if !containsStr(sink.reads, "id") {
		t.Errorf("db.Query reads = %v, want to include id", sink.reads)
	}
	// The tainted value is in the FIRST positional argument (concatenated into the
	// query string) — the dangerous, non-parameterized form.
	info, ok := sink.sinkArgs["db.Query"]
	if !ok {
		t.Fatalf("no sinkArg for db.Query: %+v", sink.sinkArgs)
	}
	if !info.firstArgTainted {
		t.Errorf("db.Query firstArgTainted = false, want true (concatenated query)")
	}
}

// TestExtractGoParameterizedQuerySafe covers the clean form: `db.Query(sql, id)`
// where id is a distinct placeholder argument, not concatenated. The tainted
// value must NOT be in the first argument, and there must be >=2 positional args.
func TestExtractGoParameterizedQuerySafe(t *testing.T) {
	src := []byte(`package s

import "database/sql"

func lookup(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query("SELECT name FROM users WHERE id = $1", id)
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "lookup")
	sink := stmtWithCall(t, u, "db.Query")
	info := sink.sinkArgs["db.Query"]
	if info.argCount < 2 {
		t.Errorf("db.Query argCount = %d, want >=2", info.argCount)
	}
	if info.firstArgTainted {
		t.Errorf("db.Query firstArgTainted = true, want false (placeholder query)")
	}
}

// TestExtractGoMethodChainRendering covers `template.New("g").Parse(src)`: the
// method-on-call-result chain must render to the full dotted callee
// template.New.Parse with the tainted argument recorded.
func TestExtractGoMethodChainRendering(t *testing.T) {
	src := []byte(`package r

import (
	"net/http"
	"text/template"
)

func greet(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("tmpl")
	tmpl, err := template.New("greeting").Parse(src)
	_ = tmpl
	_ = err
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "greet")
	sink := stmtWithCall(t, u, "template.New.Parse")
	if !containsStr(sink.reads, "src") {
		t.Errorf("template.New.Parse reads = %v, want to include src", sink.reads)
	}
}

// TestExtractGoInlineSourceHoist covers the deserialization shape:
// `gob.NewDecoder(r.Body).Decode(&env)` in an if-init. The source r.Body is used
// inline as a sink argument; the extractor must hoist it into a synthetic
// assignment so the engine can taint it. After hoisting, some statement assigns a
// synthetic temp from the r.Body chain, and gob.NewDecoder reads that temp.
func TestExtractGoInlineSourceHoist(t *testing.T) {
	src := []byte(`package s

import (
	"encoding/gob"
	"net/http"
)

func restore(r *http.Request) error {
	var env struct{ User string }
	if err := gob.NewDecoder(r.Body).Decode(&env); err != nil {
		return err
	}
	return nil
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "restore")

	// A synthetic assignment whose RHS chain is r.Body must exist.
	var tmp string
	for i := range u.stmts {
		for _, ch := range u.stmts[i].chains {
			if ch == "r.Body" && u.stmts[i].assigns != "" {
				tmp = u.stmts[i].assigns
			}
		}
	}
	if tmp == "" {
		t.Fatalf("no synthetic assignment carrying r.Body chain; stmts=%+v", u.stmts)
	}

	// The gob.NewDecoder sink must read that synthetic temp.
	sink := stmtWithCall(t, u, "gob.NewDecoder")
	if !containsStr(sink.reads, tmp) {
		t.Errorf("gob.NewDecoder reads = %v, want to include hoisted temp %q", sink.reads, tmp)
	}
}

// TestExtractGoParseErrorGraceful covers graceful degradation: a non-compiling
// snippet must not panic and must not crash the extractor. It may return whatever
// partial units the parser recovered, or none.
func TestExtractGoParseErrorGraceful(t *testing.T) {
	src := []byte(`package broken

func oops( {
	x :=
`)
	// Must not panic.
	units := extractUnits(lexctx.LangGo, src)
	_ = units
}

// TestExtractGoReceiverMethodParams covers a method with a receiver: the receiver
// name is the first parameter (position matters for interproc summaries).
func TestExtractGoReceiverMethodParams(t *testing.T) {
	src := []byte(`package s

type Server struct{}

func (s *Server) handle(input string) {
	_ = input
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "handle")
	if len(u.params) != 2 || u.params[0] != "s" || u.params[1] != "input" {
		t.Errorf("params = %v, want [s input] (receiver first)", u.params)
	}
}

// stmtAssigningReading returns the first statement in u whose Assigns == name AND
// which reads `read` — so a test can pinpoint the container-assignment statement
// (`m["c"] = user`) rather than an earlier `m := ...{}` initializer that also
// assigns the same base.
func stmtAssigningReading(t *testing.T, u unitDraft, name, read string) stmtDraft {
	t.Helper()
	for i := range u.stmts {
		if u.stmts[i].assigns == name && containsStr(u.stmts[i].reads, read) {
			return u.stmts[i]
		}
	}
	t.Fatalf("no statement assigning %q reading %q in unit %q; stmts=%+v", name, read, u.funcName, u.stmts)
	return stmtDraft{}
}

// stmtAssigning returns the first statement in u whose Assigns == name.
func stmtAssigning(t *testing.T, u unitDraft, name string) stmtDraft {
	t.Helper()
	for i := range u.stmts {
		if u.stmts[i].assigns == name {
			return u.stmts[i]
		}
	}
	t.Fatalf("no statement assigning %q in unit %q; stmts=%+v", name, u.funcName, u.stmts)
	return stmtDraft{}
}

// TestExtractGoMapIndexAssignTaintsBase covers container sensitivity for a map
// index assignment `m["c"] = user`: the extractor must record the BASE identifier
// (m), not the index expression, as the assignee so a tainted RHS taints the
// whole container (a sound container-level over-approximation).
func TestExtractGoMapIndexAssignTaintsBase(t *testing.T) {
	src := []byte(`package j

import "net/http"

func runMap(r *http.Request) {
	user := r.FormValue("c")
	m := map[string]string{}
	m["c"] = user
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "runMap")
	// The index assignment must be attributed to the base variable m.
	st := stmtAssigningReading(t, u, "m", "user")
	if !containsStr(st.reads, "user") {
		t.Errorf("m[..]=user reads = %v, want to include user", st.reads)
	}
}

// TestExtractGoStructFieldAssignTaintsBase covers container sensitivity for a
// struct-field assignment `obj.Field = user`: the base identifier (obj) is the
// assignee, so the whole struct is tainted.
func TestExtractGoStructFieldAssignTaintsBase(t *testing.T) {
	src := []byte(`package j

import "net/http"

func runField(r *http.Request) {
	user := r.FormValue("c")
	var cmd Cmd
	cmd.Arg = user
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "runField")
	st := stmtAssigning(t, u, "cmd")
	if !containsStr(st.reads, "user") {
		t.Errorf("cmd.Arg=user reads = %v, want to include user", st.reads)
	}
}

// TestExtractGoIndexAssignBaseNotOverwritingSanitized guards the clean_field_safe
// path: when the RHS of a field assignment is a sanitized value, the base is still
// the assignee (so the engine's per-class sanitizer clearing — not the extractor —
// keeps it clean). The extractor must record the base and the sanitizer call.
func TestExtractGoIndexAssignBaseRecordsSanitizerCall(t *testing.T) {
	src := []byte(`package j

import (
	"net/http"
	"strconv"
)

func runSafe(r *http.Request) {
	var t Ticket
	t.Count = strconv.Atoi(r.FormValue("count"))
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "runSafe")
	st := stmtAssigning(t, u, "t")
	if !containsStr(st.calls, "strconv.Atoi") {
		t.Errorf("t.Count=strconv.Atoi(...) calls = %v, want to include strconv.Atoi", st.calls)
	}
}

// TestExtractGoFprintfSinkArg covers the reflected-XSS-via-fmt.Fprintf shape:
// fmt.Fprintf(w, "<div>%s</div>", name) — the callee renders to fmt.Fprintf and
// the tainted interpolation variable name is captured as a tainted arg var (the
// writer w is the first positional arg, name a later one).
func TestExtractGoFprintfSinkArg(t *testing.T) {
	src := []byte(`package web

import (
	"fmt"
	"net/http"
)

func greet(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<div>%s</div>", name)
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "greet")
	sink := stmtWithCall(t, u, "fmt.Fprintf")
	if !containsStr(sink.reads, "name") {
		t.Errorf("fmt.Fprintf reads = %v, want to include name", sink.reads)
	}
	info, ok := sink.sinkArgs["fmt.Fprintf"]
	if !ok {
		t.Fatalf("no sinkArg for fmt.Fprintf: %+v", sink.sinkArgs)
	}
	if !containsStr(info.taintedArgVars, "name") {
		t.Errorf("fmt.Fprintf taintedArgVars = %v, want to include name", info.taintedArgVars)
	}
}

// TestExtractGoWriteBytesSinkArg covers w.Write([]byte("<b>"+user+"</b>")): the
// callee renders to w.Write and the tainted concat variable user is captured even
// though it is nested inside a []byte(...) conversion of a string concatenation.
func TestExtractGoWriteBytesSinkArg(t *testing.T) {
	src := []byte(`package web

import "net/http"

func greet(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	_, _ = w.Write([]byte("<b>" + user + "</b>"))
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "greet")
	sink := stmtWithCall(t, u, "w.Write")
	if !containsStr(sink.reads, "user") {
		t.Errorf("w.Write reads = %v, want to include user", sink.reads)
	}
	info := sink.sinkArgs["w.Write"]
	if !containsStr(info.taintedArgVars, "user") {
		t.Errorf("w.Write taintedArgVars = %v, want to include user", info.taintedArgVars)
	}
}

// TestExtractGoTemplateHTMLBypassSinkArg covers the auto-escape bypass shape:
// t.Execute(w, template.HTML(comment)). The nested template.HTML call must be
// captured as its own sink call with the tainted variable comment as an arg — so
// the catalog can flag template.HTML(tainted) as an XSS sink independent of the
// enclosing Execute (which is NOT a sink).
func TestExtractGoTemplateHTMLBypassSinkArg(t *testing.T) {
	src := []byte(`package web

import (
	"html/template"
	"net/http"
)

func greet(w http.ResponseWriter, r *http.Request) {
	comment := r.URL.Query().Get("comment")
	t := template.Must(template.New("c").Parse("<p>{{.}}</p>"))
	_ = t.Execute(w, template.HTML(comment))
}
`)
	units := extractUnits(lexctx.LangGo, src)
	u := findUnit(t, units, "greet")
	sink := stmtWithCall(t, u, "template.HTML")
	info, ok := sink.sinkArgs["template.HTML"]
	if !ok {
		t.Fatalf("no sinkArg for template.HTML: %+v", sink.sinkArgs)
	}
	if !containsStr(info.taintedArgVars, "comment") {
		t.Errorf("template.HTML taintedArgVars = %v, want to include comment", info.taintedArgVars)
	}
}
