package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzeClojure is the end-to-end helper for Clojure: source → units → flows.
func analyzeClojure(t *testing.T, src string) []taintFlowIDs {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t.clj", lexctx.LangClojure, []byte(src))
	flows := eng.AnalyzeFile(units)
	out := make([]taintFlowIDs, 0, len(flows))
	for i := range flows {
		out = append(out, taintFlowIDs{rule: flows[i].Sink.RuleID, class: string(flows[i].Sink.VulnClass)})
	}
	return out
}

func clojureHasRule(flows []taintFlowIDs, id string) bool {
	for _, f := range flows {
		if f.rule == id {
			return true
		}
	}
	return false
}

// TestStructuralClojureTruePositives exercises the headline Clojure injection
// classes end to end, asserting the expected rule ID fires.
func TestStructuralClojureTruePositives(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "command injection via shell/sh of a request param",
			src:  `(defn run [req] (let [cmd (:params req)] (shell/sh "sh" "-c" cmd)))`,
			want: "TAINT-002",
		},
		{
			name: "code injection via eval of a request param",
			src:  `(defn run [req] (let [form (:params req)] (eval form)))`,
			want: "TAINT-005",
		},
		{
			name: "code injection via load-string",
			src:  `(defn run [req] (let [s (:query-string req)] (load-string s)))`,
			want: "TAINT-005",
		},
		{
			name: "sql injection via jdbc string concat",
			src:  `(defn q [req] (let [id (:params req)] (jdbc/query db (str "select * from t where id=" id))))`,
			want: "TAINT-001",
		},
		{
			name: "path traversal via slurp of a tainted path",
			src:  `(defn r [req] (let [p (:params req)] (slurp p)))`,
			want: "TAINT-004",
		},
		{
			name: "ssrf via clj-http client/get of a tainted url",
			src:  `(defn f [req] (let [u (:params req)] (client/get u)))`,
			want: "TAINT-006",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flows := analyzeClojure(t, tc.src)
			if !clojureHasRule(flows, tc.want) {
				t.Errorf("want %s to fire for %q; got flows %+v", tc.want, tc.src, flows)
			}
		})
	}
}

// TestStructuralClojureCleanNoFlow pins precision: the SAFE counterparts must not
// fire. A parameterized jdbc vector keeps the value out of the SQL string, an
// Integer/parseInt coercion strips injection metacharacters, and a non-sink use of
// a tainted value carries no flow.
func TestStructuralClojureCleanNoFlow(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "parameterized jdbc vector is safe",
			src:  `(defn q [req] (let [id (:params req)] (jdbc/query db ["select * from t where id = ?" id])))`,
		},
		{
			name: "Integer/parseInt coercion defuses command injection",
			src:  `(defn run [req] (let [raw (:params req) n (Integer/parseInt raw)] (shell/sh "echo" n)))`,
		},
		{
			name: "tainted value only printed is not a sink",
			src:  `(defn log [req] (let [msg (:params req)] (println "request:" msg)))`,
		},
		{
			name: "constant command is never tainted",
			src:  `(defn run [] (shell/sh "sh" "-c" "echo done"))`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flows := analyzeClojure(t, tc.src)
			if len(flows) != 0 {
				t.Errorf("expected no flow for %q, got %+v", tc.src, flows)
			}
		})
	}
}
