(ns app.hof-construction
  "Higher-order CONSTRUCTION. `apply` and `map` DISPATCH a function and are
   re-attributed at the dispatch site. `partial`, `comp` and `as->` instead
   BUILD a function (or rename the threaded value) and invoke it through a local
   binding, so the sink never appears as a call head under any name — until the
   binding is followed. These three were added as honest false negatives when
   the suite first reached recall 1.0, and are kept as the regression pin now
   that each is modeled: a `partial`/`comp` binding is remembered lexically and
   the later call is rewritten into the calls it makes; `as->` binds and
   rebinds the author's name per stage."
  (:require [clojure.java.shell :as shell]
            [clj-http.client :as client]
            [clojure.string :as str]))

;; `partial` closes over the sink and returns a new function bound to `f`. The
;; call head is `f`, a local; `(f cmd)` is modeled as `(shell/sh "sh" "-c" cmd)`.
(defn run-partial [req]
  (let [cmd (:params req)
        f   (partial shell/sh "sh" "-c")]
    (f cmd))) ; nox-expect: TAINT-002

;; `comp` composes the sink into a new function bound to `g`. `(g url)` is
;; modeled as `(client/get (str url))`, right to left.
(defn fetch-composed [req]
  (let [url (:params req)
        g   (comp client/get str)]
    (g url))) ; nox-expect: TAINT-006

;; `as->` threads like `->`/`->>` but binds the value to a NAME the author
;; chooses; `v` is bound from `(:params req)` and rebound to each stage's result.
(defn run-as-> [req]
  (as-> (:params req) v
        (str/trim v)
        (shell/sh "sh" "-c" v))) ; nox-expect: TAINT-002
