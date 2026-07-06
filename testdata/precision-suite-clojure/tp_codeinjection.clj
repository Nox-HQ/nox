(ns app.codeinjection
  "Code injection (CWE-95): an untrusted value flows into eval / load-string,
   which re-evaluate their argument as Clojure code. A correct scanner fires
   TAINT-005.")

;; eval of a request-derived form.
(defn run-form [req]
  (let [form (:params req)]
    (eval form))) ; nox-expect: TAINT-005

;; load-string reads and evaluates a whole program string from the query string.
(defn run-script [req]
  (let [s (:query-string req)]
    (load-string s))) ; nox-expect: TAINT-005
