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
	sink := stmtWithCall(t, u, "String")
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
	st := stmtWithCall(t, u, "session.dataTask")
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
