(ns app.threading
  "Honest false-negative corner: Clojure's threading macros and higher-order
   functions reorder or indirect the argument position in ways a positional,
   straight-line FORM recognizer cannot follow. These are REAL vulnerabilities a
   correct scanner should fire, and they are annotated as such — nox is expected
   to MISS them (recall gap), which is the honest cost of recognizing a Lisp
   without a full reader/evaluator. See README.md."
  (:require [clojure.java.shell :as shell]
            [clj-http.client :as client]))

;; Thread-first `->` — still an honest FALSE NEGATIVE. The tainted value is
;; threaded as the FIRST argument of each stage, and the nested `->>` reverses
;; that position again, so it arrives at `sh` somewhere the positional FORM
;; recognizer does not track. Closing it needs a real threading-macro desugarer
;; over the s-expression tree; the HOF re-attribution below does not reach it.
(defn run-threaded [req]
  (-> (:params req)
      (clojure.string/trim)
      (->> (shell/sh "sh" "-c")))) ; nox-expect: TAINT-002

;; Higher-order dispatch via `apply` — CAUGHT. A dispatcher passes the real
;; callee as DATA, so the sink is never a literal call head; the statement is now
;; re-attributed to the dispatched symbol and the remaining args scored against
;; it. Kept as the regression test.
(defn run-apply [req]
  (let [args (:params req)]
    (apply shell/sh "sh" "-c" args))) ; nox-expect: TAINT-002

;; `map` over tainted URLs — CAUGHT by the same re-attribution as `apply`.
(defn fetch-all [req]
  (let [urls (:params req)]
    (map client/get urls))) ; nox-expect: TAINT-006
