(ns app.hof-construction
  "Honest FALSE NEGATIVES: higher-order CONSTRUCTION. `apply` and `map` DISPATCH
   a function and are modeled — the statement is re-attributed to the dispatched
   symbol. `partial`, `comp` and `as->` instead BUILD a function (or rename the
   threaded value) and invoke it through a local binding, so the sink never
   appears as a call head under any name the recognizer tracks.

   All three are real vulnerabilities a correct scanner reports. They are added
   deliberately: this suite had reached recall 1.0, at which point it could only
   catch regressions and could no longer say what a Lisp recognizer still cannot
   follow. Closing them is the way to raise the number; deleting them is not."
  (:require [clojure.java.shell :as shell]
            [clj-http.client :as client]
            [clojure.string :as str]))

;; FN: `partial` closes over the sink and returns a new function bound to `f`.
;; The call head is `f`, a local, so the shell sink is never named at the site.
(defn run-partial [req]
  (let [cmd (:params req)
        f   (partial shell/sh "sh" "-c")]
    (f cmd))) ; nox-expect: TAINT-002

;; FN: `comp` composes the sink into a new function bound to `g`. Same shape as
;; partial — the sink is a value, not a call head.
(defn fetch-composed [req]
  (let [url (:params req)
        g   (comp client/get str)]
    (g url))) ; nox-expect: TAINT-006

;; FN: `as->` threads like `->`/`->>` but binds the value to a NAME the author
;; chooses, so the threaded value is a normal local rather than the synthetic
;; binding the other threading macros are modeled with.
(defn run-as-> [req]
  (as-> (:params req) v
        (str/trim v)
        (shell/sh "sh" "-c" v))) ; nox-expect: TAINT-002
