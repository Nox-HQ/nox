package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractCPPFuncParams verifies that a C function definition
// `int f(char *a, int b)` yields a unit named `f` whose params are the binding
// names (types and pointer sigils stripped), in declaration order.
func TestExtractCPPFuncParams(t *testing.T) {
	src := []byte(`int handle(char *name, int count) {
    char *x = name;
    return 0;
}
`)
	units := extractUnits(lexctx.LangCPP, src)
	u := findUnit(t, units, "handle")
	if len(u.params) != 2 || u.params[0] != "name" || u.params[1] != "count" {
		t.Fatalf("params = %v, want [name count]", u.params)
	}
}

// TestExtractCPPMainArgv: `int main(int argc, char **argv)` binds argc and argv.
func TestExtractCPPMainArgv(t *testing.T) {
	src := []byte(`int main(int argc, char **argv) {
    return 0;
}
`)
	units := extractUnits(lexctx.LangCPP, src)
	u := findUnit(t, units, "main")
	if len(u.params) != 2 || u.params[0] != "argc" || u.params[1] != "argv" {
		t.Fatalf("params = %v, want [argc argv]", u.params)
	}
}

// TestExtractCPPVoidParams: `void f(void)` and `void f()` have no parameters.
func TestExtractCPPVoidParams(t *testing.T) {
	for _, src := range []string{
		"void f(void) {\n  return;\n}\n",
		"void f() {\n  return;\n}\n",
	} {
		units := extractUnits(lexctx.LangCPP, []byte(src))
		u := findUnit(t, units, "f")
		if len(u.params) != 0 {
			t.Errorf("params for %q = %v, want none", src, u.params)
		}
	}
}

// TestExtractCPPAssignmentFromSource: `char *name = getenv("X")` records
// assigns=name; a following bare sink call reads name.
func TestExtractCPPAssignmentFromSource(t *testing.T) {
	src := []byte(`void handle(void) {
    char *name = getenv("NAME");
    system(name);
}
`)
	units := extractUnits(lexctx.LangCPP, src)
	u := findUnit(t, units, "handle")

	assign := stmtWithCall(t, u, "getenv")
	if assign.assigns != "name" {
		t.Errorf("assign LHS = %q, want name", assign.assigns)
	}

	sink := stmtWithCall(t, u, "system")
	if !containsStr(sink.reads, "name") {
		t.Errorf("sink reads = %v, want to include name", sink.reads)
	}
}

// TestExtractCPPScopeResolutionNormalized: a C++ `std::string s = std::getenv(...)`
// normalizes `::` to `.` so the call reads as `std.getenv`, which suffix-matches
// the catalog's `getenv` key.
func TestExtractCPPScopeResolutionNormalized(t *testing.T) {
	src := []byte(`void handle() {
    std::string path = std::getenv("FILE");
    std::ifstream f(path);
}
`)
	units := extractUnits(lexctx.LangCPP, src)
	u := findUnit(t, units, "handle")

	assign := stmtWithCall(t, u, "std.getenv")
	if assign.assigns != "path" {
		t.Errorf("assign LHS = %q, want path", assign.assigns)
	}
}

// TestExtractCPPReturnStatement: a `return fopen(path);` is both a sink read and
// a return, so its returns list the read variables.
func TestExtractCPPReturnStatement(t *testing.T) {
	src := []byte(`FILE *serve(char *path) {
    return fopen(path, "r");
}
`)
	units := extractUnits(lexctx.LangCPP, src)
	u := findUnit(t, units, "serve")
	sink := stmtWithCall(t, u, "fopen")
	if !containsStr(sink.reads, "path") {
		t.Errorf("return sink reads = %v, want to include path", sink.reads)
	}
	if !containsStr(sink.returns, "path") {
		t.Errorf("return returns = %v, want to include path", sink.returns)
	}
}

// TestExtractCPPPrototypeIsNotDefinition: a function PROTOTYPE (ends in `;`) is
// not a definition header — it opens no unit.
func TestExtractCPPPrototypeIsNotDefinition(t *testing.T) {
	src := []byte(`int helper(char *a, int b);
void caller(void) {
    helper("x", 1);
}
`)
	units := extractUnits(lexctx.LangCPP, src)
	for _, u := range units {
		if u.funcName == "helper" {
			t.Fatalf("prototype `int helper(...);` must not open a unit; got unit %+v", u)
		}
	}
	// caller is a real definition.
	findUnit(t, units, "caller")
}

// TestExtractCPPCallIsNotHeader: a lone `system(cmd);` call must NOT be read as a
// function definition header (a single identifier before '(' is a call).
func TestExtractCPPCallIsNotHeader(t *testing.T) {
	src := []byte(`void run(char *cmd) {
    system(cmd);
}
`)
	units := extractUnits(lexctx.LangCPP, src)
	for _, u := range units {
		if u.funcName == "system" {
			t.Fatal("`system(cmd)` call was misread as a function definition header")
		}
	}
	u := findUnit(t, units, "run")
	stmtWithCall(t, u, "system")
}

// TestExtractCPPConstMethodHeader: a C++ member definition with a trailing
// `const` specifier (`std::string name() const { ... }`) is still recognized as
// a function header with the right name.
func TestExtractCPPConstMethodHeader(t *testing.T) {
	src := []byte(`std::string Widget::describe(char *in) const {
    return in;
}
`)
	units := extractUnits(lexctx.LangCPP, src)
	// The name is the final dotted segment after `::`->`.` normalization.
	findUnit(t, units, "describe")
}

// TestShapeCPPConstructorDecl: `std::ifstream in(path)` is a declaration whose
// initializer is a constructor call. Read literally it looks like a call to a
// function named `in` (the VARIABLE), so the constructed type never appeared as
// the callee and a sink keyed on it could not fire.
func TestShapeCPPConstructorDecl(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"    std.ifstream in(path)", "    in = std.ifstream(path)"},
		{"    std::ofstream out(p)", "    out = std::ofstream(p)"},
		{"    Foo bar(baz)", "    bar = Foo(baz)"},
		// Not the shape: leave untouched.
		{"    foo(bar)", "    foo(bar)"},                   // ordinary call
		{"    int helper(int a)", "    int helper(int a)"}, // builtin-typed prototype
		{"    return foo(bar)", "    return foo(bar)"},     // keyword head
		{"    auto x = mk(y)", "    auto x = mk(y)"},       // already an assignment
		{"    Foo bar(baz) extra", "    Foo bar(baz) extra"},
	} {
		got := shapeCPPConstructorDecl(logicalLine{line: 1, code: tc.in, raw: tc.in})
		if got.code != tc.want {
			t.Errorf("shape(%q) = %q, want %q", tc.in, got.code, tc.want)
		}
	}
}
