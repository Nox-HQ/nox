(ns app.threading
  "Threading macros and higher-order dispatch reorder or indirect the argument
   position, so the sink never appears with the tainted value as a literal
   argument. All three flows here were honest false negatives until the
   threading and HOF-dispatch models landed; they are kept as the regression
   tests for those shapes. See README.md, and clean_threading.clj for the
   companion no-false-positive guard."
  (:require [clojure.java.shell :as shell]
            [clj-http.client :as client]))

;; Thread-first `->` with a nested `->>` — CAUGHT. The threaded value is modeled
;; as a synthetic binding that each stage reads and rebinds, and a nested
;; threading form used as a stage re-threads that same value. Kept as the
;; regression test for the mixed `->` / `->>` shape.
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
