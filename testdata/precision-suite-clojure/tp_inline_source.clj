(ns app.inline-source
  "True positives: the source reaches the sink without ever being bound to a
   name, or through a top-level def. Both are the ordinary shape and both were
   invisible: the inline scan was C-like (`ident(args)`) and saw no calls in a
   Lisp form, and a top-level def was never joined into the functions that read
   it."
  (:require [clojure.java.shell :as shell]
            [clojure.java.jdbc :as jdbc]))

(def db {:dbtype "postgresql" :dbname "app"})

;; Source straight into the sink argument.
(defn run-inline [req]
  (shell/sh "sh" "-c" (:params req))) ; nox-expect: TAINT-002

;; `str` is not a sanitizer: wrapping the source in it clears nothing.
(defn run-wrapped [req]
  (let [cmd (str "echo " (:params req))]
    (shell/sh "sh" "-c" cmd))) ; nox-expect: TAINT-002

;; A top-level def bound from the environment reaches a defn that reads it.
(def target (System/getenv "TARGET"))

(defn ping []
  (shell/sh "sh" "-c" target)) ; nox-expect: TAINT-002

;; Source concatenated into the SQL string, inline.
(defn find-user [req]
  (jdbc/query db (str "select * from users where name = '" (:params req) "'"))) ; nox-expect: TAINT-001
