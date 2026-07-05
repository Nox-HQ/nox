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
