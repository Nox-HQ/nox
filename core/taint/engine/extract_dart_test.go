package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractDartFunctionParams pins Dart parameter binding: the bare parameter
// NAME is extracted from a `Type name` declaration, ignoring the type.
func TestExtractDartFunctionParams(t *testing.T) {
	src := []byte(`String handle(String a, Uri b, int c) {
    var x = a;
    return x;
}
`)
	units := extractUnits(lexctx.LangDart, src)
	u := findUnit(t, units, "handle")
	for _, want := range []string{"a", "b", "c"} {
		if !containsStr(u.params, want) {
			t.Errorf("params = %v, want to include %q", u.params, want)
		}
	}
	// The types must NOT be parameters.
	for _, bad := range []string{"String", "Uri", "int"} {
		if containsStr(u.params, bad) {
			t.Errorf("params = %v, type %q must not be a parameter name", u.params, bad)
		}
	}
}

// TestExtractDartNamedParams: Dart named parameters `{required String name}` and
// optional positional `[int x]` still yield the bare binding name.
func TestExtractDartNamedParams(t *testing.T) {
	src := []byte(`void handle(String cmd, {required String name, int count = 0}) {
    var x = name;
}
`)
	units := extractUnits(lexctx.LangDart, src)
	u := findUnit(t, units, "handle")
	for _, want := range []string{"cmd", "name", "count"} {
		if !containsStr(u.params, want) {
			t.Errorf("params = %v, want to include %q", u.params, want)
		}
	}
}

// TestExtractDartVarFinalConst covers Dart's binding keywords: `var`, `final`,
// `const`, and a typed `Type lhs = rhs`. All yield the bare LHS name.
func TestExtractDartVarFinalConst(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{"void f() {\n var u = args;\n}\n", "u"},
		{"void f() {\n final u = args;\n}\n", "u"},
		{"void f() {\n const u = args;\n}\n", "u"},
		{"void f() {\n String u = args;\n}\n", "u"},
		{"void f() {\n final String u = args;\n}\n", "u"},
	}
	for _, tc := range cases {
		units := extractUnits(lexctx.LangDart, []byte(tc.src))
		u := findUnit(t, units, "f")
		found := false
		for i := range u.stmts {
			if u.stmts[i].assigns == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("src %q: want an assignment to %q, got units %+v", tc.src, tc.want, u.stmts)
		}
	}
}

// TestExtractDartSourceAssignmentAndSink covers the core shape: a `var lhs =
// source` binding, then a sink call reading the tainted variable.
func TestExtractDartSourceAssignmentAndSink(t *testing.T) {
	src := []byte(`void run() {
    var name = Platform.environment['REPORT'];
    Process.run('sh', ['-c', 'echo $name']);
}
`)
	units := extractUnits(lexctx.LangDart, src)
	u := findUnit(t, units, "run")
	assign := stmtWithChain(t, u, "Platform.environment")
	if assign.assigns != "name" {
		t.Errorf("assign LHS = %q, want name", assign.assigns)
	}
}

// TestExtractDartReturnStatement recognizes `return x` and records the returned
// variable while still capturing calls/reads in the returned expression.
func TestExtractDartReturnStatement(t *testing.T) {
	src := []byte(`String load(String p) {
    return File(p).readAsStringSync();
}
`)
	units := extractUnits(lexctx.LangDart, src)
	u := findUnit(t, units, "load")
	sink := stmtWithCall(t, u, "readAsStringSync")
	if !containsStr(sink.reads, "p") {
		t.Errorf("reads = %v, want to include p", sink.reads)
	}
	if !containsStr(sink.returns, "p") {
		t.Errorf("returns = %v, want to include p", sink.returns)
	}
}

// TestExtractDartHeaderNotACall guards that a function header is NOT mis-read as
// a call to the function name.
func TestExtractDartHeaderNotACall(t *testing.T) {
	src := []byte(`void fetch(String url) {
    var x = url;
}
`)
	units := extractUnits(lexctx.LangDart, src)
	u := findUnit(t, units, "fetch")
	for i := range u.stmts {
		if containsStr(u.stmts[i].calls, "fetch") {
			t.Errorf("header must not be read as a call to fetch: %+v", u.stmts[i])
		}
	}
}

// TestExtractDartMethodSuffix covers method-suffix matching for varying
// receivers: a call `db.rawQuery(sql)` records the callee suffix `rawQuery` so
// the catalog can match a receiver-varying sink.
func TestExtractDartMethodSuffix(t *testing.T) {
	src := []byte(`void f(String id) {
    var sql = "SELECT * FROM t WHERE id = $id";
    db.rawQuery(sql);
}
`)
	units := extractUnits(lexctx.LangDart, src)
	u := findUnit(t, units, "f")
	st := stmtWithCall(t, u, "db.rawQuery")
	if !containsStr(st.reads, "sql") {
		t.Errorf("reads = %v, want to include sql", st.reads)
	}
}

// TestExtractDartAsyncHeader recognizes an `async` function header and a header
// with a leading return type / modifiers.
func TestExtractDartAsyncHeader(t *testing.T) {
	src := []byte(`Future<void> doWork(String label) async {
    var y = label;
}
`)
	units := extractUnits(lexctx.LangDart, src)
	u := findUnit(t, units, "doWork")
	if !containsStr(u.params, "label") {
		t.Errorf("params = %v, want to include label", u.params)
	}
}

// TestExtractDartBareCall covers a bare call statement (no assignment) reading a
// tainted variable — the second recognized statement shape.
func TestExtractDartBareCall(t *testing.T) {
	src := []byte(`void f(String url) {
    http.get(Uri.parse(url));
}
`)
	units := extractUnits(lexctx.LangDart, src)
	u := findUnit(t, units, "f")
	st := stmtWithCall(t, u, "http.get")
	if !containsStr(st.reads, "url") {
		t.Errorf("reads = %v, want to include url", st.reads)
	}
}

// TestExtractDartInterpolationRead: a `$var` / `${expr}` interpolation splices a
// tainted value into a string; lexctx classifies the hole as CODE, so the
// assignment's RHS reads the interpolated variable.
func TestExtractDartInterpolationRead(t *testing.T) {
	src := []byte(`void f(String id) {
    var sql = 'SELECT * FROM users WHERE id = $id';
}
`)
	units := extractUnits(lexctx.LangDart, src)
	u := findUnit(t, units, "f")
	found := false
	for i := range u.stmts {
		if u.stmts[i].assigns == "sql" && containsStr(u.stmts[i].reads, "id") {
			found = true
		}
	}
	if !found {
		t.Errorf("assignment to sql should read interpolated id, got units %+v", u.stmts)
	}
}
