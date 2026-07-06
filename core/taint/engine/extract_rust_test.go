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

// extractorSeedFor returns the synthetic source-seed statement the extractor
// emits for a web-extractor parameter binding `name` (assigns == name and a
// catalog-source call), or nil if none was emitted. The seed lets the engine
// treat the parameter as tainted-on-entry.
func extractorSeedFor(u unitDraft, name string) *stmtDraft {
	for i := range u.stmts {
		if u.stmts[i].assigns == name && len(u.stmts[i].calls) > 0 {
			return &u.stmts[i]
		}
	}
	return nil
}

// TestExtractRustExtractorParamActix: an actix handler whose parameter type is a
// `web::Query<_>` extractor seeds the binding as a taint source. The synthetic
// seed statement assigns the binding and carries a catalog source call
// (normalized `web.Query`).
func TestExtractRustExtractorParamActix(t *testing.T) {
	src := []byte(`
async fn run(query: web::Query<Params>) {
    let _ = query.cmd;
}
`)
	units := extractUnits(lexctx.LangRust, src)
	u := findUnit(t, units, "run")
	if len(u.params) != 1 || u.params[0] != "query" {
		t.Fatalf("params = %v, want [query]", u.params)
	}
	seed := extractorSeedFor(u, "query")
	if seed == nil {
		t.Fatalf("no extractor seed statement for `query` in %+v", u.stmts)
	}
	if seed.calls[0] != "web.Query" {
		t.Errorf("seed call = %q, want web.Query", seed.calls[0])
	}
}

// TestExtractRustExtractorParamAxumDestructured: an axum handler whose parameter
// is the destructured `Query(params): Query<Params>` form seeds the INNER
// binding `params` (the value actually used), not the type name.
func TestExtractRustExtractorParamAxumDestructured(t *testing.T) {
	src := []byte(`
async fn run(Query(params): Query<Params>) {
    let _ = params.cmd;
}
`)
	units := extractUnits(lexctx.LangRust, src)
	u := findUnit(t, units, "run")
	seed := extractorSeedFor(u, "params")
	if seed == nil {
		t.Fatalf("no extractor seed statement for `params` in %+v (params=%v)", u.stmts, u.params)
	}
	if seed.calls[0] != "Query" {
		t.Errorf("seed call = %q, want Query", seed.calls[0])
	}
}

// TestExtractRustExtractorParamForms covers the other actix/axum extractor
// wrappers (Form/Json/Path) in both the named and destructured shapes.
func TestExtractRustExtractorParamForms(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		binding  string
		wantCall string
	}{
		{"actix web::Form", "async fn h(form: web::Form<P>) {}", "form", "web.Form"},
		{"actix web::Json", "async fn h(body: web::Json<P>) {}", "body", "web.Json"},
		{"actix web::Path", "async fn h(p: web::Path<String>) {}", "p", "web.Path"},
		{"axum Json destructured", "async fn h(Json(payload): Json<P>) {}", "payload", "Json"},
		{"axum Path destructured", "async fn h(Path(id): Path<String>) {}", "id", "Path"},
		{"axum Form named", "async fn h(form: Form<P>) {}", "form", "Form"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			units := extractUnits(lexctx.LangRust, []byte("\n"+tc.src+"\n"))
			u := findUnit(t, units, "h")
			seed := extractorSeedFor(u, tc.binding)
			if seed == nil {
				t.Fatalf("no extractor seed for %q in %+v", tc.binding, u.stmts)
			}
			if seed.calls[0] != tc.wantCall {
				t.Errorf("seed call = %q, want %q", seed.calls[0], tc.wantCall)
			}
		})
	}
}

// TestExtractRustNonExtractorParamNoSeed is the precision guardrail: a normal
// typed parameter (`id: i64`, `cfg: &Config`) must NOT be seeded as a source, or
// nox would false-positive on every function. No seed statement is emitted.
func TestExtractRustNonExtractorParamNoSeed(t *testing.T) {
	src := []byte(`
async fn run(id: i64, cfg: &Config, name: String) {
    let _ = id;
}
`)
	units := extractUnits(lexctx.LangRust, src)
	u := findUnit(t, units, "run")
	for _, p := range []string{"id", "cfg", "name"} {
		if seed := extractorSeedFor(u, p); seed != nil {
			t.Errorf("param %q was seeded as a source (%+v); non-extractor params must not taint", p, seed)
		}
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
