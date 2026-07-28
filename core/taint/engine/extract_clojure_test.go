package engine

import (
	"strings"
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

// TestExtractClojureHOFDispatch: `apply` and `map` pass the real callee as DATA,
// so a sink reached through them never appears as a literal call head and the
// flow was invisible. The statement is re-attributed to the dispatched symbol.
func TestExtractClojureHOFDispatch(t *testing.T) {
	for _, tc := range []struct {
		name, src, wantCallee, wantRead string
	}{
		{"apply", "(defn f [req]\n  (let [args (:params req)]\n    (apply shell/sh \"sh\" \"-c\" args)))\n", "shell/sh", "args"},
		{"map", "(defn f [req]\n  (let [urls (:params req)]\n    (map client/get urls)))\n", "client/get", "urls"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			units := extractUnits(lexctx.LangClojure, []byte(tc.src))
			u := findUnit(t, units, "f")
			var found *stmtDraft
			for i := range u.stmts {
				for _, c := range u.stmts[i].calls {
					if c == tc.wantCallee {
						found = &u.stmts[i]
					}
				}
			}
			if found == nil {
				t.Fatalf("dispatched callee %q not attributed: %+v", tc.wantCallee, u.stmts)
			}
			if !containsStr(found.reads, tc.wantRead) {
				t.Errorf("reads = %v, want to include %q", found.reads, tc.wantRead)
			}
		})
	}
}

// TestExtractClojureHOFDispatchKeepsInlineFn is the precision guard: only a bare
// SYMBOL is re-attributed. An inline `#(...)` or `fn` literal has no name to
// attribute the flow to and must leave the dispatcher as the callee.
func TestExtractClojureHOFDispatchKeepsInlineFn(t *testing.T) {
	src := []byte("(defn f [req]\n  (let [urls (:params req)]\n    (map #(str % \"x\") urls)))\n")
	units := extractUnits(lexctx.LangClojure, src)
	u := findUnit(t, units, "f")
	for _, st := range u.stmts {
		for _, c := range st.calls {
			if c == "#" || c == "%" {
				t.Errorf("inline fn literal re-attributed as callee %q: %+v", c, st)
			}
		}
	}
}

// TestExtractClojureThreading: a threading macro rewrites argument position at
// read time, so a value threaded into a sink never appears as a literal argument
// of it. The threaded value is modeled as a synthetic binding each stage reads
// and rebinds — carrying evidence alone was not enough, because the engine
// taints a variable at its BINDING and reports a sink that READS one.
func TestExtractClojureThreading(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"thread-first", "(defn f [req]\n  (-> (:params req)\n      (shell/sh)))\n"},
		{"mixed-first-last", "(defn f [req]\n  (-> (:params req)\n      (->> (shell/sh \"sh\" \"-c\"))))\n"},
		{"some-arrow", "(defn f [req]\n  (some-> (:params req)\n          (shell/sh)))\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			units := extractUnits(lexctx.LangClojure, []byte(tc.src))
			u := findUnit(t, units, "f")
			var sink *stmtDraft
			for i := range u.stmts {
				if containsStr(u.stmts[i].calls, "shell/sh") {
					sink = &u.stmts[i]
				}
			}
			if sink == nil {
				t.Fatalf("threaded sink not recognized: %+v", u.stmts)
			}
			// The stage must READ the synthetic threaded variable, which is what
			// carries the taint from the initial expression.
			threaded := false
			for _, r := range sink.reads {
				if strings.HasPrefix(r, "__nox_threaded_") {
					threaded = true
				}
			}
			if !threaded {
				t.Errorf("sink does not read the threaded value; reads=%v", sink.reads)
			}
		})
	}
}

// TestExtractClojureThreadingRebinds: each stage rebinds the threaded variable,
// so the value keeps flowing down the chain AND a sanitizing stage can clear it.
func TestExtractClojureThreadingRebinds(t *testing.T) {
	src := "(defn f [req]\n  (-> (:params req)\n      (clojure.string/trim)\n      (shell/sh)))\n"
	units := extractUnits(lexctx.LangClojure, []byte(src))
	u := findUnit(t, units, "f")
	rebinds := 0
	for _, st := range u.stmts {
		if strings.HasPrefix(st.assigns, "__nox_threaded_") {
			rebinds++
		}
	}
	// One initial binding plus one per stage.
	if rebinds < 3 {
		t.Errorf("expected the threaded variable to be bound then rebound per stage, got %d: %+v", rebinds, u.stmts)
	}
}

// TestClojureLiteralMapKeysAreNotSources: a keyword is a source only in
// FUNCTION position — `(:headers req)` READS a request. As a KEY in a map
// literal it CONSTRUCTS one, which every test fixture, mock and benchmark does.
// Treating literal keys as source reads marked those fixtures untrusted; 8 false
// positives were measured on real Clojure projects before this was fixed.
func TestClojureLiteralMapKeysAreNotSources(t *testing.T) {
	// A hand-built request map must not taint the binding.
	built := []byte("(defn f []\n  (let [request {:headers {\"a\" \"b\"} :body \"x\" :uri \"/p\"}]\n    (slurp request)))\n")
	units := extractUnits(lexctx.LangClojure, built)
	u := findUnit(t, units, "f")
	for _, st := range u.stmts {
		for _, c := range st.chains {
			if c == "headers" || c == "body" || c == "uri" {
				t.Errorf("literal map key %q recorded as a source chain: %+v", c, st)
			}
		}
	}

	// A keyword ACCESS on a request must still resolve as a source.
	access := []byte("(defn g [req]\n  (let [h (:headers req)]\n    (slurp h)))\n")
	units2 := extractUnits(lexctx.LangClojure, access)
	u2 := findUnit(t, units2, "g")
	sawSource := false
	for _, st := range u2.stmts {
		for _, c := range st.chains {
			if c == "headers" {
				sawSource = true
			}
		}
	}
	if !sawSource {
		t.Errorf("a keyword ACCESS must still resolve as a source: %+v", u2.stmts)
	}
}
