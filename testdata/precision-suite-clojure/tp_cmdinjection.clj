(ns app.cmdinjection
  "Command injection (CWE-78): an untrusted Ring request value is executed as a
   command line via clojure.java.shell/sh. A correct scanner fires TAINT-002."
  (:require [clojure.java.shell :as shell]))

;; A request param passed straight to `sh -c` runs the tainted string as a
;; command line.
(defn run-cmd [req]
  (let [cmd (:params req)]
    (shell/sh "sh" "-c" cmd))) ; nox-expect: TAINT-002

;; The value flows through a rebinding before the sink; taint must survive it.
(defn deploy [req]
  (let [target (:query-string req)
        arg    target]
    (shell/sh "bash" "-c" arg))) ; nox-expect: TAINT-002
