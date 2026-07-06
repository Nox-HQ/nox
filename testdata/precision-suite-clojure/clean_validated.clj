(ns app.validated
  "Clean: input used only in non-sink positions, or logged/printed rather than
   executed. Any finding here is a false positive."
  (:require [clojure.string :as str]))

;; A request value echoed to a log is not executed as a command.
(defn log-request [req]
  (let [msg (:params req)]
    (println "request:" msg)))

;; Building a response map from the tainted value carries no sink.
(defn handler [req]
  (let [q (:query-string req)]
    {:status 200
     :body   (str "you searched for " q)}))

;; A parse-long coercion followed by arithmetic yields a number, not an
;; injectable string.
(defn paginate [req]
  (let [raw  (:params req)
        page (parse-long raw)]
    (* page 25)))
