(ns app.pathtraversal
  "Path traversal (CWE-22): a request-controlled path is read with slurp /
   clojure.java.io/reader, reading an attacker-chosen file. A correct scanner
   fires TAINT-004."
  (:require [clojure.java.io :as io]))

;; slurp of a tainted path.
(defn read-config [req]
  (let [path (:params req)]
    (slurp path))) ; nox-expect: TAINT-004

;; io/reader opens a tainted path.
(defn open-file [req]
  (let [p (:query-string req)]
    (io/reader p))) ; nox-expect: TAINT-004
