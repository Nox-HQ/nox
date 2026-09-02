package engine

import (
	"reflect"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Higher-order CONSTRUCTION: `partial` and `comp` BUILD a function that is
// invoked through a local name, and `as->` binds the threaded value to a name
// the author chooses. In all three the sink never appears as a call head under
// a name the recognizer tracks unless the construction is followed.
func TestClojureHOFConstruction(t *testing.T) {
	const ns = `(ns app.t
  (:require [clojure.java.shell :as shell]
            [clj-http.client :as client]
            [clojure.string :as str]))
`
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"partial bound by let", ns + `
(defn run [req]
  (let [cmd (:params req)
        f   (partial shell/sh "sh" "-c")]
    (f cmd)))
`, []string{"TAINT-002"}},
		{"partial bound by def, invoked in a defn", ns + `
(def run-it (partial shell/sh "sh" "-c"))
(defn run [req]
  (let [cmd (:params req)]
    (run-it cmd)))
`, []string{"TAINT-002"}},
		{"partial of a non-sink", ns + `
(defn run [req]
  (let [cmd (:params req)
        f   (partial str "prefix-")]
    (f cmd)))
`, nil},
		{"partial over a sanitized argument", ns + `
(defn run [req]
  (let [raw (:params req)
        n   (Integer/parseInt raw)
        f   (partial shell/sh "sleep")]
    (f n)))
`, nil},
		{"partial alias is lexical", ns + `
(defn run [req]
  (let [cmd (:params req)]
    (let [f (partial shell/sh "sh" "-c")]
      (count f))
    (let [f (partial str "x")]
      (f cmd))))
`, nil},
		{"comp bound by let", ns + `
(defn fetch [req]
  (let [url (:params req)
        g   (comp client/get str)]
    (g url)))
`, []string{"TAINT-006"}},
		{"comp with a sanitizer inside", ns + `
(defn fetch [req]
  (let [n (:params req)
        g (comp shell/sh Integer/parseInt)]
    (g n)))
`, nil},
		{"comp of non-sinks", ns + `
(defn fetch [req]
  (let [url (:params req)
        g   (comp str/trim str)]
    (g url)))
`, nil},
		{"as-> binds the threaded value", ns + `
(defn run [req]
  (as-> (:params req) v
        (str/trim v)
        (shell/sh "sh" "-c" v)))
`, []string{"TAINT-002"}},
		{"as-> through a sanitizer", ns + `
(defn run [req]
  (as-> (:params req) v
        (Integer/parseInt v)
        (shell/sh "sleep" v)))
`, nil},
		{"as-> from a clean value", ns + `
(defn run [req]
  (as-> "ls" v
        (str/trim v)
        (shell/sh "sh" "-c" v)))
`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeRuleIDs(t, "t.clj", lexctx.LangClojure, tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}
