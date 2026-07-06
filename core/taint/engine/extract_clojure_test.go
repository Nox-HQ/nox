package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractClojureDef: `(def NAME expr)` is a binding whose assignee is NAME and
// whose RHS reads flow from expr.
func TestExtractClojureDef(t *testing.T) {
	src := []byte(`(def cmd (get params "cmd"))`)
	units := extractUnits(lexctx.LangClojure, src)
	u := findUnit(t, units, "")
	if len(u.stmts) == 0 {
		t.Fatalf("no statements extracted: %+v", units)
	}
	st := stmtAssigning(t, u, "cmd")
	if st.assigns != "cmd" {
		t.Fatalf("assigns = %q, want cmd", st.assigns)
	}
	// The RHS calls `get` (and reads params) so a source can flow in.
	if !containsStr(st.calls, "get") {
		t.Errorf("def RHS should surface the get call; calls=%v", st.calls)
	}
}

// TestExtractClojureLetBindings: `(let [a expr1 b expr2] body)` binds a and b,
// each with its own RHS reads.
func TestExtractClojureLetBindings(t *testing.T) {
	src := []byte(`(let [user (:params req) c user] (sh "sh" "-c" c))`)
	units := extractUnits(lexctx.LangClojure, src)
	u := findUnit(t, units, "")
	stUser := stmtAssigning(t, u, "user")
	if stUser.assigns != "user" {
		t.Fatalf("let did not bind user: %+v", u.stmts)
	}
	stC := stmtAssigning(t, u, "c")
	if !containsStr(stC.reads, "user") {
		t.Errorf("binding c should read user; reads=%v", stC.reads)
	}
	// The body `(sh ...)` is a call.
	if stmtWithCall(t, u, "sh").line == 0 {
		t.Errorf("sh call in let body not recognized: %+v", u.stmts)
	}
}

// TestExtractClojureCallHead: a bare `(CALLEE args...)` is a call whose callee is
// the head symbol and whose args surface as reads.
func TestExtractClojureCallHead(t *testing.T) {
	src := []byte(`(def x (:params req)) (eval x)`)
	units := extractUnits(lexctx.LangClojure, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "eval")
	if sink.line == 0 {
		t.Fatalf("eval call not recognized: %+v", u.stmts)
	}
	if !containsStr(sink.reads, "x") {
		t.Errorf("eval reads = %v, want to include x", sink.reads)
	}
}

// TestExtractClojureDefn: `(defn name [params] body)` opens a unit keyed by name
// with its positional parameters.
func TestExtractClojureDefn(t *testing.T) {
	src := []byte(`(defn run-cmd [req other] (sh (:params req)))`)
	units := extractUnits(lexctx.LangClojure, src)
	u := findUnit(t, units, "run-cmd")
	if u.funcName != "run-cmd" {
		t.Fatalf("expected run-cmd unit, got %+v", units)
	}
	if len(u.params) != 2 || u.params[0] != "req" || u.params[1] != "other" {
		t.Errorf("params = %v, want [req other]", u.params)
	}
	if stmtWithCall(t, u, "sh").line == 0 {
		t.Errorf("sh call inside defn body not recognized: %+v", u.stmts)
	}
}

// TestExtractClojureThreadingIsNotBinding guards precision: a `->` threading macro
// is a call form, not a `def`, so it must not be misread as binding a variable
// named `->`.
func TestExtractClojureThreadingNotDef(t *testing.T) {
	src := []byte(`(-> x (foo) (bar))`)
	units := extractUnits(lexctx.LangClojure, src)
	u := findUnit(t, units, "")
	for _, st := range u.stmts {
		if st.assigns == "->" {
			t.Errorf("threading macro must not bind `->`: %+v", st)
		}
	}
}

// TestExtractClojureJdbcParamShape: a parameterized jdbc query `(jdbc/query db
// ["... ?" v])` passes the tainted value as a vector bind parameter, so the sink
// arg shape records ArgCount>=2 (the SQL string + the value) with the taint NOT in
// the first positional — enabling the parameterized-query safe path. A
// string-concat query `(jdbc/query db (str "... " v))` must instead put the taint
// in the first positional.
func TestExtractClojureJdbcConcatFirstArg(t *testing.T) {
	src := []byte(`(defn q [req]
  (let [id (:id (:params req))]
    (jdbc/query db (str "select * from t where id = " id))))`)
	units := extractUnits(lexctx.LangClojure, src)
	u := findUnit(t, units, "q")
	sink := stmtWithCall(t, u, "jdbc/query")
	if sink.line == 0 {
		t.Fatalf("jdbc/query not recognized: %+v", u.stmts)
	}
	info, ok := sink.sinkArgs["jdbc/query"]
	if !ok {
		t.Fatalf("no sinkArg for jdbc/query: %+v", sink.sinkArgs)
	}
	// The string-concat query interpolates the tainted id into the SQL string
	// argument, so the taint IS in a positional slot the danger check treats as
	// unsafe (first positional after the db handle carries it).
	if !containsStr(info.taintedArgVars, "id") {
		t.Errorf("jdbc/query concat should carry id as a tainted arg; got %+v", info)
	}
}
