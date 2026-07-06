package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractLuaFunctionParamsAndCall pins the core recognizer shapes for Lua: a
// `function name(a, b)` header with positional params, a `local` assignment, and a
// bare call that reads the assigned variable.
func TestExtractLuaFunctionParamsAndCall(t *testing.T) {
	src := []byte(`function handle(req, res)
  local cmd = req.query
  os.execute("echo " .. cmd)
end
`)
	units := extractUnits(lexctx.LangLua, src)
	u := findUnit(t, units, "handle")
	if len(u.params) != 2 || u.params[0] != "req" || u.params[1] != "res" {
		t.Fatalf("params = %v, want [req res]", u.params)
	}
	sink := stmtWithCall(t, u, "os.execute")
	found := false
	for _, r := range sink.reads {
		if r == "cmd" {
			found = true
		}
	}
	if !found {
		t.Errorf("os.execute stmt reads = %v, want to include cmd", sink.reads)
	}
}

// TestExtractLuaLocalFunctionHeader: `local function name(...)` is recognized the
// same as `function name(...)`.
func TestExtractLuaLocalFunctionHeader(t *testing.T) {
	src := []byte(`local function run(path)
  return io.open(path)
end
`)
	units := extractUnits(lexctx.LangLua, src)
	u := findUnit(t, units, "run")
	if len(u.params) != 1 || u.params[0] != "path" {
		t.Fatalf("params = %v, want [path]", u.params)
	}
}

// TestExtractLuaLocalAssignment: `local x = rhs` binds the bare name x as the LHS.
func TestExtractLuaLocalAssignment(t *testing.T) {
	src := []byte(`local user = os.getenv("USER")
os.execute(user)
`)
	units := extractUnits(lexctx.LangLua, src)
	u := findUnit(t, units, "")
	var assign stmtDraft
	for i := range u.stmts {
		if u.stmts[i].assigns == "user" {
			assign = u.stmts[i]
		}
	}
	if assign.assigns != "user" {
		t.Fatalf("no `local user = ...` assignment recognized: %+v", u.stmts)
	}
	if len(assign.calls) == 0 || assign.calls[0] != "os.getenv" {
		t.Errorf("assignment calls = %v, want [os.getenv]", assign.calls)
	}
}

// TestExtractLuaPlainAssignment: `x = rhs` (no `local`) is also an assignment.
func TestExtractLuaPlainAssignment(t *testing.T) {
	src := []byte(`cmd = arg[1]
os.execute(cmd)
`)
	units := extractUnits(lexctx.LangLua, src)
	u := findUnit(t, units, "")
	found := false
	for i := range u.stmts {
		if u.stmts[i].assigns == "cmd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("plain `cmd = ...` assignment not recognized: %+v", u.stmts)
	}
}

// TestExtractLuaMethodCall: a method call `obj:method(args)` is normalized so the
// callee resolves to the dotted chain `obj.method` the catalog keys on.
func TestExtractLuaMethodCall(t *testing.T) {
	src := []byte(`function q(db, id)
  db:exec("SELECT * FROM t WHERE id = " .. id)
end
`)
	units := extractUnits(lexctx.LangLua, src)
	u := findUnit(t, units, "q")
	sink := stmtWithCall(t, u, "db.exec")
	if sink.line == 0 {
		t.Fatalf("method call db:exec not normalized to db.exec: %+v", u.stmts)
	}
	found := false
	for _, r := range sink.reads {
		if r == "id" {
			found = true
		}
	}
	if !found {
		t.Errorf("db.exec stmt reads = %v, want to include id", sink.reads)
	}
}

// TestExtractLuaDottedCall: a `obj.method(args)` dotted chain resolves directly.
func TestExtractLuaDottedCall(t *testing.T) {
	src := []byte(`function f(u)
  local h = ngx.req.get_uri_args()
  os.execute(u)
end
`)
	units := extractUnits(lexctx.LangLua, src)
	u := findUnit(t, units, "f")
	if stmtWithCall(t, u, "ngx.req.get_uri_args").line == 0 {
		t.Fatalf("dotted call ngx.req.get_uri_args not recognized")
	}
}

// TestExtractLuaReturn: `return expr` records the returned variables while still
// capturing calls/reads in the expression.
func TestExtractLuaReturn(t *testing.T) {
	src := []byte(`local function wrap(x)
  return x
end
`)
	units := extractUnits(lexctx.LangLua, src)
	u := findUnit(t, units, "wrap")
	if len(u.stmts) == 0 {
		t.Fatalf("no statements extracted for wrap")
	}
	ret := u.stmts[len(u.stmts)-1]
	found := false
	for _, r := range ret.returns {
		if r == "x" {
			found = true
		}
	}
	if !found {
		t.Errorf("return returns = %v, want to include x", ret.returns)
	}
}

// TestExtractLuaBareCall: a bare call statement `loadstring(code)` is recognized.
func TestExtractLuaBareCall(t *testing.T) {
	src := []byte(`local code = io.read()
loadstring(code)
`)
	units := extractUnits(lexctx.LangLua, src)
	u := findUnit(t, units, "")
	if stmtWithCall(t, u, "loadstring").line == 0 {
		t.Fatalf("bare loadstring call not recognized: %+v", u.stmts)
	}
}
