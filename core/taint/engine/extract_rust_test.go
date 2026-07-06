package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractRustFnParams verifies that `fn name(a: T, b: U)` yields a unit
// named `name` whose params are the binding names before each `:` (types
// stripped), in declaration order.
func TestExtractRustFnParams(t *testing.T) {
	src := []byte(`
fn handle(name: String, count: u32) {
    let x = name;
}
`)
	units := extractUnits(lexctx.LangRust, src)
	u := findUnit(t, units, "handle")
	if len(u.params) != 2 || u.params[0] != "name" || u.params[1] != "count" {
		t.Fatalf("params = %v, want [name count]", u.params)
	}
}

// TestExtractRustSelfParam: a method with `&self` / `&mut self` receiver keeps
// self in the parameter list (its position matters for arg mapping) alongside
// the real parameters.
func TestExtractRustSelfParam(t *testing.T) {
	src := []byte(`
fn run(&self, cmd: String) {
    let y = cmd;
}
`)
	units := extractUnits(lexctx.LangRust, src)
	u := findUnit(t, units, "run")
	if len(u.params) != 2 || u.params[0] != "self" || u.params[1] != "cmd" {
		t.Fatalf("params = %v, want [self cmd]", u.params)
	}
}

// TestExtractRustLetAssignment: `let q = source()` records assigns=q; a
// following bare sink call reads q.
func TestExtractRustLetAssignment(t *testing.T) {
	src := []byte(`
fn handle(req: HttpRequest) {
    let q = env::var("ID");
    Command::new(q);
}
`)
	units := extractUnits(lexctx.LangRust, src)
	u := findUnit(t, units, "handle")

	assign := stmtWithCall(t, u, "env.var")
	if assign.assigns != "q" {
		t.Errorf("assign LHS = %q, want q", assign.assigns)
	}

	sink := stmtWithCall(t, u, "Command.new")
	found := false
	for _, r := range sink.reads {
		if r == "q" {
			found = true
		}
	}
	if !found {
		t.Errorf("sink reads = %v, want to include q", sink.reads)
	}
}

// TestExtractRustLetMut: `let mut x = e` strips the `mut` and binds x.
func TestExtractRustLetMut(t *testing.T) {
	src := []byte(`
fn f() {
    let mut path = read_input();
}
`)
	units := extractUnits(lexctx.LangRust, src)
	u := findUnit(t, units, "f")
	if len(u.stmts) == 0 || u.stmts[0].assigns != "path" {
		t.Fatalf("let mut binding = %q, want path (stmts=%+v)", firstAssign(u), u.stmts)
	}
}

// TestExtractRustLetTypedBinding: `let s: String = e` strips the type annotation
// and binds s.
func TestExtractRustLetTypedBinding(t *testing.T) {
	src := []byte(`
fn f() {
    let s: String = read_input();
}
`)
	units := extractUnits(lexctx.LangRust, src)
	u := findUnit(t, units, "f")
	if len(u.stmts) == 0 || u.stmts[0].assigns != "s" {
		t.Fatalf("typed binding = %q, want s (stmts=%+v)", firstAssign(u), u.stmts)
	}
}

// TestExtractRustExplicitReturn: `return x;` records x in returns.
func TestExtractRustExplicitReturn(t *testing.T) {
	src := []byte(`
fn get(req: HttpRequest) -> String {
    let v = req.body();
    return v;
}
`)
	units := extractUnits(lexctx.LangRust, src)
	u := findUnit(t, units, "get")
	var ret *stmtDraft
	for i := range u.stmts {
		if len(u.stmts[i].returns) > 0 {
			ret = &u.stmts[i]
		}
	}
	if ret == nil {
		t.Fatalf("no return statement found in %+v", u.stmts)
	}
	found := false
	for _, r := range ret.returns {
		if r == "v" {
			found = true
		}
	}
	if !found {
		t.Errorf("returns = %v, want to include v", ret.returns)
	}
}

// TestExtractRustBareCall: a bare call statement `foo(x);` is recognized with
// its callee and argument reads.
func TestExtractRustBareCall(t *testing.T) {
	src := []byte(`
fn f(user: String) {
    fs::read(user);
}
`)
	units := extractUnits(lexctx.LangRust, src)
	u := findUnit(t, units, "f")
	sink := stmtWithCall(t, u, "fs.read")
	found := false
	for _, r := range sink.reads {
		if r == "user" {
			found = true
		}
	}
	if !found {
		t.Errorf("bare-call reads = %v, want to include user", sink.reads)
	}
}

// TestExtractRustMethodChain: a method chain `a.b().c(x)` still surfaces the
// argument read x (pragmatic — chains are coarse but arg reads must survive).
func TestExtractRustMethodChain(t *testing.T) {
	src := []byte(`
fn f(url: String) {
    let resp = reqwest::Client::new().get(url).send();
}
`)
	units := extractUnits(lexctx.LangRust, src)
	u := findUnit(t, units, "f")
	if len(u.stmts) == 0 {
		t.Fatal("no statements extracted from a method chain")
	}
	found := false
	for _, st := range u.stmts {
		for _, r := range st.reads {
			if r == "url" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("method-chain reads did not include url: %+v", u.stmts)
	}
}

// firstAssign is a tiny test helper returning the first statement's assigns
// (or "" when there are none) for clearer failure messages.
func firstAssign(u unitDraft) string {
	if len(u.stmts) == 0 {
		return ""
	}
	return u.stmts[0].assigns
}
