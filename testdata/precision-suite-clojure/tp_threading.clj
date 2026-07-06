(ns app.threading
  "Honest false-negative corner: Clojure's threading macros and higher-order
   functions reorder or indirect the argument position in ways a positional,
   straight-line FORM recognizer cannot follow. These are REAL vulnerabilities a
   correct scanner should fire, and they are annotated as such — nox is expected
   to MISS them (recall gap), which is the honest cost of recognizing a Lisp
   without a full reader/evaluator. See README.md."
  (:require [clojure.java.shell :as shell]
            [clj-http.client :as client]))

;; Thread-first `->`: the tainted value is threaded as the FIRST argument of each
;; stage, so it arrives at `sh` in a position the flat recognizer does not track.
(defn run-threaded [req]
  (-> (:params req)
      (clojure.string/trim)
      (->> (shell/sh "sh" "-c")))) ; nox-expect: TAINT-002

;; Higher-order dispatch: the sink is applied via `apply` over a tainted seq, so
;; the value never appears as a literal argument of the sink call.
(defn run-apply [req]
  (let [args (:params req)]
    (apply shell/sh "sh" "-c" args))) ; nox-expect: TAINT-002

;; `map` over tainted URLs: each fetch is an SSRF, but the taint flows through a
;; HOF the recognizer does not model.
(defn fetch-all [req]
  (let [urls (:params req)]
    (map client/get urls))) ; nox-expect: TAINT-006
