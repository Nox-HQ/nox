(ns app.ssrf
  "SSRF (CWE-918): a tainted URL is fetched with clj-http. Unlike command
   injection, validation of the string does not help — the request still goes to
   the attacker-chosen host — so a correct scanner fires TAINT-006."
  (:require [clj-http.client :as client]))

;; clj-http GET of a request-controlled URL.
(defn fetch [req]
  (let [url (:params req)]
    (client/get url))) ; nox-expect: TAINT-006

;; A POST to a tainted URL is equally an SSRF vector.
(defn push [req]
  (let [target (:query-string req)]
    (client/post target))) ; nox-expect: TAINT-006
