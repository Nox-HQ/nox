package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestScopeFunctionBindingKotlin: `source().let { cmd -> sink(cmd) }` pipes the
// source straight into the lambda with no intermediate `val`, so the parameter
// was never bound and the sink saw a clean value. The parameter aliases the
// receiver and is now bound to it.
func TestScopeFunctionBindingKotlin(t *testing.T) {
	src := []byte("class R {\n  fun run(request: HttpServletRequest) {\n    request.getParameter(\"cmd\").let { cmd ->\n      Runtime.getRuntime().exec(cmd)\n    }\n  }\n}\n")
	units := extractUnits(lexctx.LangKotlin, src)
	u := findUnit(t, units, "run")
	var bound stmtDraft
	for i := range u.stmts {
		if u.stmts[i].assigns == "cmd" {
			bound = u.stmts[i]
		}
	}
	if bound.assigns != "cmd" {
		t.Fatalf("lambda parameter not bound to its receiver: %+v", u.stmts)
	}
	if !containsStr(bound.calls, "request.getParameter") {
		t.Errorf("binding should carry the receiver's source call; calls=%v", bound.calls)
	}
}

// TestScopeFunctionBindingGroovy: the Groovy `with { c -> }` form is the same
// aliasing as Kotlin's `let`.
func TestScopeFunctionBindingGroovy(t *testing.T) {
	src := []byte("class R {\n  def go(request) {\n    request.getParameter(\"cmd\").with { c ->\n      c.execute()\n    }\n  }\n}\n")
	units := extractUnits(lexctx.LangGroovy, src)
	u := findUnit(t, units, "go")
	found := false
	for i := range u.stmts {
		if u.stmts[i].assigns == "c" {
			found = true
		}
	}
	if !found {
		t.Errorf("with{} parameter not bound to its receiver: %+v", u.stmts)
	}
}

// TestScopeFunctionBindingImplicitIt: a lambda with no declared parameter binds
// the implicit `it`.
func TestScopeFunctionBindingImplicitIt(t *testing.T) {
	ll := logicalLine{line: 1, code: `request.getParameter(     ).let {`, raw: `request.getParameter("cmd").let {`}
	b, ok := scopeFunctionBinding(ll)
	if !ok {
		t.Fatal("implicit-it lambda not recognized")
	}
	if b.code != "it = request.getParameter(     )" {
		t.Errorf("binding = %q, want the receiver bound to it", b.code)
	}
}

// TestScopeFunctionBindingRejectsNonAlias is the precision guard: only the pure
// receiver-scoping functions alias their receiver. A collection function binds
// an ELEMENT, and a typed/destructuring parameter is not a plain alias — neither
// may be turned into a binding.
func TestScopeFunctionBindingRejectsNonAlias(t *testing.T) {
	for _, code := range []string{
		`items.each { item ->`, // collection element, not the receiver
		`items.collect { x ->`, // ditto
		`items.map { x ->`,     // ditto
		`foo.let { (a, b) ->`,  // destructuring parameter
		`foo.bar { x ->`,       // not a scope function
		`someExpr {`,           // no receiver dot
	} {
		if b, ok := scopeFunctionBinding(logicalLine{line: 1, code: code, raw: code}); ok {
			t.Errorf("%q must not bind, got %q", code, b.code)
		}
	}
}
