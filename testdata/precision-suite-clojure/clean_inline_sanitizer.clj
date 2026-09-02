(ns app.inline-sanitizer
  "Clean: the sanitizer wraps the source IN the binding — `(Integer/parseInt
   (:params req))` — or wraps it straight in the sink argument. clean_safe_db.clj
   binds the raw value first and coerces it on a second line; this file pins the
   one-line forms, which used to fire because the engine ignored a sanitizer on
   the same line as its source. A finding on any line here is a false positive."
  (:require [clojure.java.shell :as shell]
            [clojure.java.jdbc :as jdbc]))

(def db {:dbtype "postgresql" :dbname "app"})

;; Coerced on the binding line.
(defn sleep-for [req]
  (let [n (Integer/parseInt (:params req))]
    (shell/sh "sleep" n)))

;; Coerced inside the sink argument, no name at all.
(defn count-to [req]
  (shell/sh "seq" (Integer/parseInt (:params req))))

;; A top-level def coerced where it is bound.
(def limit (parse-long (System/getenv "LIMIT")))

(defn head-lines []
  (shell/sh "head" "-n" limit))

;; An inline source inside a parameterized bind vector is a placeholder value.
(defn find-user [req]
  (jdbc/query db ["select * from users where id = ?" (:params req)]))
