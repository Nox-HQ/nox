package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractSwiftFunctionParams pins Swift parameter binding: the INTERNAL
// binding name is extracted (not the external argument label). `_ a`, `label b`,
// and bare `c` all bind `a`, `b`, `c` respectively.
func TestExtractSwiftFunctionParams(t *testing.T) {
	src := []byte(`func handle(_ a: String, to b: URL, c: Int) {
    let x = a
}
`)
	units := extractUnits(lexctx.LangSwift, src)
	u := findUnit(t, units, "handle")
	for _, want := range []string{"a", "b", "c"} {
		if !containsStr(u.params, want) {
			t.Errorf("params = %v, want to include %q (internal binding name)", u.params, want)
		}
	}
	// The external label `to` must NOT be a parameter.
	if containsStr(u.params, "to") {
		t.Errorf("params = %v, external label `to` must not be a binding name", u.params)
	}
}

// TestExtractSwiftLetAssignmentAndCall covers the core shape: a `let lhs = source`
// binding, then a bare sink call reading the tainted variable.
func TestExtractSwiftLetAssignmentAndCall(t *testing.T) {
	src := []byte(`func run() {
    let name = ProcessInfo.processInfo.environment["REPORT"]
    Process.launch(name)
}
`)
	units := extractUnits(lexctx.LangSwift, src)
	u := findUnit(t, units, "run")

	assign := stmtWithChain(t, u, "ProcessInfo.processInfo.environment")
	if assign.assigns != "name" {
		t.Errorf("assign LHS = %q, want name", assign.assigns)
	}
	sink := stmtWithCall(t, u, "Process.launch")
	if !containsStr(sink.reads, "name") {
		t.Errorf("sink reads = %v, want to include name", sink.reads)
	}
}

// TestExtractSwiftVarAssignment covers `var lhs = rhs` (mutable binding) — the
// LHS name is bound the same as `let`.
func TestExtractSwiftVarAssignment(t *testing.T) {
	src := []byte(`func f() {
    var u = CommandLine.arguments
    print(u)
}
`)
	units := extractUnits(lexctx.LangSwift, src)
	u := findUnit(t, units, "f")
	st := stmtWithChain(t, u, "CommandLine.arguments")
	if st.assigns != "u" {
		t.Errorf("assign LHS = %q, want u", st.assigns)
	}
}

// TestExtractSwiftLetWithTypeAnnotation strips a `: Type` annotation from the
// binding so the bare name is the LHS (`let x: String = e` -> `x`).
func TestExtractSwiftLetWithTypeAnnotation(t *testing.T) {
	src := []byte(`func f() {
    let path: String = CommandLine.arguments[1]
    let data = try? Data(contentsOf: URL(fileURLWithPath: path))
}
`)
	units := extractUnits(lexctx.LangSwift, src)
	u := findUnit(t, units, "f")
	st := stmtWithChain(t, u, "CommandLine.arguments")
	if st.assigns != "path" {
		t.Errorf("assign LHS = %q, want path (annotation stripped)", st.assigns)
	}
}

// TestExtractSwiftReturnStatement recognizes `return x` and records the returned
// variable while still capturing the calls/reads in the returned expression.
func TestExtractSwiftReturnStatement(t *testing.T) {
	src := []byte(`func load(_ p: String) -> String {
    return try String(contentsOfFile: p)
}
`)
	units := extractUnits(lexctx.LangSwift, src)
	u := findUnit(t, units, "load")
	sink := stmtWithCall(t, u, "String.contentsOfFile")
	if !containsStr(sink.returns, "p") {
		t.Errorf("returns = %v, want to include p", sink.returns)
	}
	if !containsStr(sink.reads, "p") {
		t.Errorf("reads = %v, want to include p (the returned expr still reads p)", sink.reads)
	}
}

// TestExtractSwiftHeaderNotACall guards that a function header is NOT mis-read as
// a call to the function name.
func TestExtractSwiftHeaderNotACall(t *testing.T) {
	src := []byte(`func fetch(_ url: String) {
    let x = url
}
`)
	units := extractUnits(lexctx.LangSwift, src)
	u := findUnit(t, units, "fetch")
	for i := range u.stmts {
		if containsStr(u.stmts[i].calls, "fetch") {
			t.Errorf("header must not be read as a call to fetch: %+v", u.stmts[i])
		}
	}
}

// TestExtractSwiftMethodSuffix covers method-suffix matching for varying
// receivers: a call `client.dataTask(with: req)` records the callee suffix
// `dataTask` so the catalog can match a receiver-varying sink.
func TestExtractSwiftMethodSuffix(t *testing.T) {
	src := []byte(`func f(_ req: URLRequest) {
    let t = session.dataTask(with: req)
}
`)
	units := extractUnits(lexctx.LangSwift, src)
	u := findUnit(t, units, "f")
	st := stmtWithCall(t, u, "session.dataTask.with")
	if !containsStr(st.reads, "req") {
		t.Errorf("reads = %v, want to include req", st.reads)
	}
}

// TestExtractSwiftModifiersHeader recognizes a header carrying access/other
// modifiers (`public`, `static`, `override`, `@discardableResult`, generics).
func TestExtractSwiftModifiersHeader(t *testing.T) {
	src := []byte(`public static func doWork<T>(_ input: T, name label: String) {
    let y = label
}
`)
	units := extractUnits(lexctx.LangSwift, src)
	u := findUnit(t, units, "doWork")
	if !containsStr(u.params, "input") {
		t.Errorf("params = %v, want to include input", u.params)
	}
	if !containsStr(u.params, "label") {
		t.Errorf("params = %v, want to include label (internal name after external `name`)", u.params)
	}
}

// TestExtractSwiftLabelFold pins the precision-critical normalization: a
// discriminating first-argument label is folded into the callee so the catalog
// keys on the dangerous file/URL/HTML form (`String.contentsOfFile`,
// `Data.contentsOf`, `URL.string`, `dataTask.with`) while a plain conversion
// (`String(x)`) or a safe local-file initializer (`URL(fileURLWithPath:)`) does
// NOT collide with a sink key.
func TestExtractSwiftLabelFold(t *testing.T) {
	cases := []struct {
		src      string
		wantCall string
	}{
		{"func f(_ p: String) {\n let d = String(contentsOfFile: p)\n}\n", "String.contentsOfFile"},
		{"func f(_ u: URL) {\n let d = Data(contentsOf: u)\n}\n", "Data.contentsOf"},
		{"func f(_ s: String) {\n let u = URL(string: s)\n}\n", "URL.string"},
		{"func f(_ r: URLRequest) {\n let t = session.dataTask(with: r)\n}\n", "session.dataTask.with"},
	}
	for _, tc := range cases {
		units := extractUnits(lexctx.LangSwift, []byte(tc.src))
		u := findUnit(t, units, "f")
		found := false
		for i := range u.stmts {
			if containsStr(u.stmts[i].calls, tc.wantCall) {
				found = true
			}
		}
		if !found {
			t.Errorf("src %q: want folded call %q in some statement, got units %+v", tc.src, tc.wantCall, u.stmts)
		}
	}

	// A plain String(x) conversion must NOT fold to a sink form.
	units := extractUnits(lexctx.LangSwift, []byte("func f(_ x: Int) {\n let s = String(x)\n}\n"))
	u := findUnit(t, units, "f")
	for i := range u.stmts {
		if containsStr(u.stmts[i].calls, "String.contentsOfFile") {
			t.Errorf("plain String(x) must not fold to a path-traversal sink: %+v", u.stmts[i])
		}
	}
	// URL(fileURLWithPath:) is the safe local-file form: label is NOT
	// discriminating, so the callee stays `URL` (not the SSRF `URL.string`).
	units = extractUnits(lexctx.LangSwift, []byte("func f(_ p: String) {\n let u = URL(fileURLWithPath: p)\n}\n"))
	u = findUnit(t, units, "f")
	for i := range u.stmts {
		if containsStr(u.stmts[i].calls, "URL.string") {
			t.Errorf("URL(fileURLWithPath:) must not fold to the SSRF URL.string sink: %+v", u.stmts[i])
		}
	}
}

// TestExtractSwiftBareCall covers a bare call statement (no assignment) reading a
// tainted variable — the second recognized statement shape.
func TestExtractSwiftBareCall(t *testing.T) {
	src := []byte(`func f(_ html: String) {
    webView.loadHTMLString(html, baseURL: nil)
}
`)
	units := extractUnits(lexctx.LangSwift, src)
	u := findUnit(t, units, "f")
	st := stmtWithCall(t, u, "webView.loadHTMLString")
	if !containsStr(st.reads, "html") {
		t.Errorf("reads = %v, want to include html", st.reads)
	}
}
