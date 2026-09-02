package engine

import (
	"reflect"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A source used INLINE — sanitized on the line that binds it, or passed
// straight into the sink without a name — is the ordinary Clojure shape.
// Both needed a Lisp-aware inline scan: the C-like `ident(args)` walk that
// serves the other languages sees no calls in `(shell/sh "sh" "-c" (:params req))`.
func TestClojureInlineSource(t *testing.T) {
	const ns = `(ns app.t
  (:require [clojure.java.shell :as shell]
            [clojure.java.jdbc :as jdbc]))
`
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"parseInt around the source on the binding line", ns + `
(defn run [req]
  (let [n (Integer/parseInt (:params req))]
    (shell/sh "sleep" n)))
`, nil},
		{"the raw binding still fires", ns + `
(defn run [req]
  (let [n (:params req)]
    (shell/sh "sleep" n)))
`, []string{"TAINT-002"}},
		{"parse-long around a def", ns + `
(def limit (parse-long (System/getenv "LIMIT")))
(defn run []
  (shell/sh "sleep" limit))
`, nil},
		{"the raw def fires", ns + `
(def limit (System/getenv "LIMIT"))
(defn run []
  (shell/sh "sleep" limit))
`, []string{"TAINT-002"}},
		{"a str wrapping the source is not a sanitizer", ns + `
(defn run [req]
  (let [n (str "x" (:params req))]
    (shell/sh "sleep" n)))
`, []string{"TAINT-002"}},
		{"source straight into the sink", ns + `
(defn run [req]
  (shell/sh "sh" "-c" (:params req)))
`, []string{"TAINT-002"}},
		{"source sanitized straight into the sink", ns + `
(defn run [req]
  (shell/sh "sleep" (Integer/parseInt (:params req))))
`, nil},
		{"source in a jdbc bind vector is parameterized", ns + `
(defn run [db req]
  (jdbc/query db ["select * from t where id = ?" (:params req)]))
`, nil},
		// Ring's :body is an InputStream by contract: slurp READS it, it never
		// opens a path. Measured on ring and reitit, every (slurp (:body …)) —
		// request or response — was this shape and none was a file read.
		{"slurp of a request body is request I/O, not a path", ns + `
(defn read-body [req]
  (slurp (:body req)))
`, nil},
		{"slurp of a bound body is not a path either", ns + `
(defn read-body [req]
  (let [body (:body req)]
    (slurp body)))
`, nil},
		{"the body once read still reaches a sql sink", ns + `
(defn find-user [db req]
  (let [name (slurp (:body req))]
    (jdbc/query db (str "select * from users where name = '" name "'"))))
`, []string{"TAINT-001"}},
		{"source concatenated into the jdbc query string", ns + `
(defn run [db req]
  (jdbc/query db (str "select * from t where id = " (:params req))))
`, []string{"TAINT-001"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := analyzeRuleIDs(t, "t.clj", lexctx.LangClojure, c.src)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v\n%s", got, c.want, c.src)
			}
		})
	}
}
