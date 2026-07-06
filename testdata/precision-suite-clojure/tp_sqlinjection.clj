(ns app.sqlinjection
  "SQL injection (CWE-89): a request value is interpolated into a SQL string via
   `str` concatenation and handed to clojure.java.jdbc/query. A correct scanner
   fires TAINT-001. (The parameterized [\"... ?\" v] vector form is the safe
   counterpart — see clean_safe_db.clj.)"
  (:require [clojure.java.jdbc :as jdbc]))

(def db {:dbtype "postgresql" :dbname "app"})

;; String-concatenated query: the tainted id is interpolated into the SQL text.
(defn find-user [req]
  (let [id (:params req)]
    (jdbc/query db (str "select * from users where id = " id)))) ; nox-expect: TAINT-001

;; execute! with a concatenated statement is equally injectable.
(defn delete-user [req]
  (let [uid (:query-string req)]
    (jdbc/execute! db (str "delete from users where id = " uid)))) ; nox-expect: TAINT-001
