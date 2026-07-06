package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractJavaMethodAndCall covers the core shape: a typed local declaration
// assigned from a source call, then a sink call reading the tainted variable.
// It asserts the method name, its parameters in order, the declared LHS name
// (with the Java type stripped), and the sink's reads.
func TestExtractJavaMethodAndCall(t *testing.T) {
	src := []byte(`package com.example;

class Handler {
	void run(HttpServletRequest request, HttpServletResponse response) {
		String name = request.getParameter("report");
		Runtime.getRuntime().exec("gen " + name);
	}
}
`)
	units := extractUnits(lexctx.LangJava, src)
	u := findUnit(t, units, "run")

	if len(u.params) != 2 || u.params[0] != "request" || u.params[1] != "response" {
		t.Errorf("params = %v, want [request response]", u.params)
	}

	assign := stmtWithCall(t, u, "request.getParameter")
	if assign.assigns != "name" {
		t.Errorf("assign LHS = %q, want name (Java type must be stripped)", assign.assigns)
	}

	sink := stmtWithCall(t, u, "exec")
	if !containsStr(sink.reads, "name") {
		t.Errorf("sink reads = %v, want to include name", sink.reads)
	}
}

// TestExtractJavaReturnCall covers a `return stmt.executeQuery(... + id);` — the
// return must carry the sink call and read the tainted variable.
func TestExtractJavaReturnCall(t *testing.T) {
	src := []byte(`package com.example;

class Store {
	ResultSet lookup(HttpServletRequest request, Statement stmt) {
		String id = request.getParameter("id");
		return stmt.executeQuery("SELECT * FROM t WHERE id = '" + id + "'");
	}
}
`)
	units := extractUnits(lexctx.LangJava, src)
	u := findUnit(t, units, "lookup")

	ret := stmtWithCall(t, u, "stmt.executeQuery")
	if !containsStr(ret.reads, "id") {
		t.Errorf("return-sink reads = %v, want to include id", ret.reads)
	}
	if !containsStr(ret.returns, "id") {
		t.Errorf("return vars = %v, want to include id", ret.returns)
	}
}

// TestExtractJavaParamShapes exercises the parameter-name parser across the
// realistic declaration shapes: generics, arrays, varargs, annotations, final.
func TestExtractJavaParamShapes(t *testing.T) {
	src := []byte(`class C {
	void m(final String a, Map<String, String> b, int[] c, String... rest) {
		int x = 1;
	}
}
`)
	units := extractUnits(lexctx.LangJava, src)
	u := findUnit(t, units, "m")
	want := []string{"a", "b", "c", "rest"}
	if len(u.params) != len(want) {
		t.Fatalf("params = %v, want %v", u.params, want)
	}
	for i := range want {
		if u.params[i] != want[i] {
			t.Errorf("param[%d] = %q, want %q", i, u.params[i], want[i])
		}
	}
}

// TestExtractJavaScopePerMethod pins that two methods are separate units, so a
// source in one and a sink in another are NOT joined intraprocedurally (they
// could still join via a summary, but here there is no call between them).
func TestExtractJavaScopePerMethod(t *testing.T) {
	src := []byte(`class C {
	void reader(HttpServletRequest request) {
		String u = request.getParameter("u");
	}
	void sinker() {
		Runtime.getRuntime().exec("static");
	}
}
`)
	units := extractUnits(lexctx.LangJava, src)
	reader := findUnit(t, units, "reader")
	sinker := findUnit(t, units, "sinker")
	if len(reader.stmts) == 0 {
		t.Error("reader unit should carry the source read")
	}
	if len(sinker.stmts) == 0 {
		t.Error("sinker unit should carry the exec call")
	}
	// The tainted var `u` must not leak into the sinker unit.
	for _, st := range sinker.stmts {
		if containsStr(st.reads, "u") {
			t.Error("taint var u leaked across method scopes")
		}
	}
}
