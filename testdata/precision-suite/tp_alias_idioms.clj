;; True positives for the ordinary Clojure alias idioms.
;;
;; The catalog handled aliasing by ENUMERATING the aliases its author expected
;; -- `shell/sh` beside `clojure.java.shell/sh`, `io/reader`, `jdbc/query`. That
;; matches only the alias someone anticipated, and the one it anticipated for
;; clojure.java.shell was `shell`. The canonical alias is `sh` -- it is the one
;; in that namespace's own docstring -- and it was silently missed:
;;
;;   (:require [clojure.java.shell :as shell])   shell/sh   MATCHED
;;   (:require [clojure.java.shell :as sh])      sh/sh      missed
;;   (:require [clojure.java.shell :as sh2])     sh2/sh     missed
;;
;; The suite had no Clojure sample at all, so it scored 1.00 while the engine
;; was blind to the dominant spelling of its highest-severity Clojure sink. If a
;; future change drops `:as` resolution, recall here falls and says so.
(ns precision.alias-idioms
  (:require [clojure.java.shell :as sh]
            [clojure.java.io :as file-io]
            [clj-http.client :as http-client]))

(defn canonical-alias [req]
  (let [cmd (:params req)]
    (sh/sh "sh" "-c" cmd)))          ;; nox-expect: TAINT-002

(defn unanticipated-alias [req]
  (let [p (:params req)]
    (file-io/reader p)))             ;; nox-expect: TAINT-004

(defn aliased-http [req]
  (let [url (:query-string req)]
    (http-client/get url)))          ;; nox-expect: TAINT-006
