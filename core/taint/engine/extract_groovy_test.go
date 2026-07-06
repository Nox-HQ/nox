package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractGroovyMethodAndCall covers the core shape: a `def` declaration
// assigned from a source call, then a sink call reading the tainted variable. It
// asserts the method name, its parameters in order, the declared LHS name (`def`
// stripped), and the sink's reads.
func TestExtractGroovyMethodAndCall(t *testing.T) {
	src := []byte(`package com.example

class Handler {
    def run(request, response) {
        def name = request.getParameter("report")
        "generate ${name}".execute()
    }
}
`)
	units := extractUnits(lexctx.LangGroovy, src)
	u := findUnit(t, units, "run")

	if len(u.params) != 2 || u.params[0] != "request" || u.params[1] != "response" {
		t.Errorf("params = %v, want [request response]", u.params)
	}

	assign := stmtWithCall(t, u, "request.getParameter")
	if assign.assigns != "name" {
		t.Errorf("assign LHS = %q, want name (Groovy `def` must be stripped)", assign.assigns)
	}

	sink := stmtWithCall(t, u, "execute")
	if !containsStr(sink.reads, "name") {
		t.Errorf("sink reads = %v, want to include name", sink.reads)
	}
}

// TestExtractGroovyTypedDecl: a typed `String id = rhs` and typed method params
// must resolve to the bare names.
func TestExtractGroovyTypedDecl(t *testing.T) {
	src := []byte(`class C {
    String lookup(String id, Sql sql) {
        String q = "SELECT * FROM users WHERE id = '" + id + "'"
        return sql.rows(q)
    }
}
`)
	units := extractUnits(lexctx.LangGroovy, src)
	u := findUnit(t, units, "lookup")
	if len(u.params) != 2 || u.params[0] != "id" || u.params[1] != "sql" {
		t.Errorf("params = %v, want [id sql]", u.params)
	}
	q := stmtWithAssign(t, u, "q")
	if !containsStr(q.reads, "id") {
		t.Errorf("q reads = %v, want to include id (typed decl LHS must strip type)", q.reads)
	}
	ret := stmtWithCall(t, u, "sql.rows")
	if !containsStr(ret.returns, "q") {
		t.Errorf("return reads = %v / returns = %v, want returns to include q", ret.reads, ret.returns)
	}
}

// TestExtractGroovyDSLBlockNotMethod: a bare `node('label') { ... }` DSL block
// (Jenkins pipeline) must NOT be parsed as a method declaration — it folds into
// the script/module unit. This keeps the DSL receiver from becoming a spurious
// named unit.
func TestExtractGroovyDSLBlockNotMethod(t *testing.T) {
	src := []byte(`node('build') {
    def cmd = params.CMD
    sh("run ${cmd}")
}
`)
	units := extractUnits(lexctx.LangGroovy, src)
	for _, u := range units {
		if u.funcName == "node" {
			t.Fatalf("DSL block `node(...) { }` must not be treated as a method unit")
		}
	}
	// The statements land in the module unit (funcName ""): the source read and
	// the sh sink must both be present.
	mod := findUnit(t, units, "")
	if stmtWithChainSource(mod, "params.CMD") == nil {
		t.Errorf("module unit should contain the params.CMD source read")
	}
}

// TestExtractGroovyBareCall: a paren-less/`.execute()` bare call statement is
// recognized as a call-bearing statement.
func TestExtractGroovyBareCall(t *testing.T) {
	src := []byte(`class C {
    def m(request) {
        def cmd = request.getParameter("cmd")
        cmd.execute()
    }
}
`)
	units := extractUnits(lexctx.LangGroovy, src)
	u := findUnit(t, units, "m")
	sink := stmtWithCall(t, u, "cmd.execute")
	if !containsStr(sink.reads, "cmd") {
		t.Errorf("execute reads = %v, want to include cmd", sink.reads)
	}
}

// stmtWithAssign returns the first statement in u whose LHS is name, failing if
// none. A local helper mirroring stmtWithCall.
func stmtWithAssign(t *testing.T, u unitDraft, name string) stmtDraft {
	t.Helper()
	for i := range u.stmts {
		if u.stmts[i].assigns == name {
			return u.stmts[i]
		}
	}
	t.Fatalf("no statement assigning %q in unit %q", name, u.funcName)
	return stmtDraft{}
}

// stmtWithChainSource returns the first statement in u that reads the given dotted
// source chain, or nil.
func stmtWithChainSource(u unitDraft, chain string) *stmtDraft {
	for i := range u.stmts {
		for _, c := range u.stmts[i].chains {
			if c == chain {
				return &u.stmts[i]
			}
		}
	}
	return nil
}
