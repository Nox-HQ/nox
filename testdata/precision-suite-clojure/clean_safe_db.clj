(ns app.safe-db
  "Clean: the SAFE counterparts of the tp_*.clj flows. None of these should fire —
   each routes the tainted value through a parameterized query, a numeric
   coercion, or a non-sink position. A finding on any line here is a false
   positive."
  (:require [clojure.java.jdbc :as jdbc]
            [clojure.java.shell :as shell]))

(def db {:dbtype "postgresql" :dbname "app"})

;; Parameterized query: the tainted id is passed as a bind value in the
;; ["... ?" v] vector, NOT interpolated into the SQL string. Safe.
(defn find-user [req]
  (let [id (:params req)]
    (jdbc/query db ["select * from users where id = ?" id])))

;; execute! with a placeholder + bind value is safe.
(defn delete-user [req]
  (let [uid (:query-string req)]
    (jdbc/execute! db ["delete from users where id = ?" uid])))

;; Integer/parseInt coerces the value to a number, stripping every injection
;; metacharacter before it reaches the command sink.
(defn run-count [req]
  (let [raw (:params req)
        n   (Integer/parseInt raw)]
    (shell/sh "echo" n)))

;; A constant command string is never tainted.
(defn banner []
  (shell/sh "sh" "-c" "echo deploy done"))
