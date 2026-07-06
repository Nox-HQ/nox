package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractKotlinFunAndCall covers the core shape: a `val` declaration assigned
// from a source call, then a sink call reading the tainted variable. It asserts
// the function name, its parameters in order (name stripped from `name: Type`),
// the declared LHS name, and the sink's reads.
func TestExtractKotlinFunAndCall(t *testing.T) {
	src := []byte(`package com.example

class Handler {
    fun run(request: HttpServletRequest, response: HttpServletResponse) {
        val name = request.getParameter("report")
        Runtime.getRuntime().exec("gen " + name)
    }
}
`)
	units := extractUnits(lexctx.LangKotlin, src)
	u := findUnit(t, units, "run")

	if len(u.params) != 2 || u.params[0] != "request" || u.params[1] != "response" {
		t.Errorf("params = %v, want [request response]", u.params)
	}

	assign := stmtWithCall(t, u, "request.getParameter")
	if assign.assigns != "name" {
		t.Errorf("assign LHS = %q, want name (Kotlin `val` must be stripped)", assign.assigns)
	}

	sink := stmtWithCall(t, u, "exec")
	if !containsStr(sink.reads, "name") {
		t.Errorf("sink reads = %v, want to include name", sink.reads)
	}
}

// TestExtractKotlinVarDeclWithTypeAnnotation: a `val x: String = rhs` declares x
// with an explicit type annotation; the LHS must resolve to the bare name.
func TestExtractKotlinVarDeclWithTypeAnnotation(t *testing.T) {
	src := []byte(`class C {
    fun m(request: HttpServletRequest) {
        val id: String = request.getParameter("id")
        val cmd = "echo " + id
    }
}
`)
	units := extractUnits(lexctx.LangKotlin, src)
	u := findUnit(t, units, "m")
	assign := stmtWithCall(t, u, "request.getParameter")
	if assign.assigns != "id" {
		t.Errorf("assign LHS = %q, want id (type annotation must be stripped)", assign.assigns)
	}
}

// TestExtractKotlinReturnCall covers a `return stmt.executeQuery(... + id)` — the
// return must carry the sink call and read the tainted variable.
func TestExtractKotlinReturnCall(t *testing.T) {
	src := []byte(`class Store {
    fun lookup(request: HttpServletRequest, stmt: Statement): ResultSet {
        val id = request.getParameter("id")
        return stmt.executeQuery("SELECT * FROM t WHERE id = '" + id + "'")
    }
}
`)
	units := extractUnits(lexctx.LangKotlin, src)
	u := findUnit(t, units, "lookup")

	ret := stmtWithCall(t, u, "stmt.executeQuery")
	if !containsStr(ret.reads, "id") {
		t.Errorf("return-sink reads = %v, want to include id", ret.reads)
	}
	if !containsStr(ret.returns, "id") {
		t.Errorf("return vars = %v, want to include id", ret.returns)
	}
}

// TestExtractKotlinParamShapes exercises the parameter-name parser across
// realistic Kotlin declaration shapes: generics, nullable types, defaults, and
// `vararg`.
func TestExtractKotlinParamShapes(t *testing.T) {
	src := []byte(`class C {
    fun m(a: String, b: Map<String, String>, c: Int? = 0, vararg rest: String) {
        val x = 1
    }
}
`)
	units := extractUnits(lexctx.LangKotlin, src)
	u := findUnit(t, units, "m")
	want := []string{"a", "b", "c", "rest"}
	if len(u.params) != len(want) {
		t.Fatalf("params = %v, want %v", u.params, want)
	}
	for i := range want {
		if u.params[i] != want[i] {
			t.Errorf("params[%d] = %q, want %q", i, u.params[i], want[i])
		}
	}
}

// TestExtractKotlinStructuralLinesIgnored: class/import/control headers carry no
// dataflow and must not be recognized as calls that pollute a unit.
func TestExtractKotlinStructuralLinesIgnored(t *testing.T) {
	src := []byte(`package com.example

import java.io.File

class Handler {
    fun run(request: HttpServletRequest) {
        if (request != null) {
            val p = request.getParameter("path")
            File(p).readText()
        }
    }
}
`)
	units := extractUnits(lexctx.LangKotlin, src)
	u := findUnit(t, units, "run")
	// The File(...) constructor sink must read the tainted p.
	sink := stmtWithCall(t, u, "File")
	if !containsStr(sink.reads, "p") {
		t.Errorf("File sink reads = %v, want to include p", sink.reads)
	}
	// `if`/`import`/`class`/`package` lines must not be treated as calls.
	for _, u := range units {
		for _, st := range u.stmts {
			for _, c := range st.calls {
				if c == "if" || c == "class" || c == "import" || c == "package" {
					t.Errorf("structural keyword %q recognized as a call", c)
				}
			}
		}
	}
}
