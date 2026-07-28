(ns app.clean-threading
  "Clean stressor for the threading-macro model. Threading is THE idiomatic
   Clojure control shape — `->`, `->>`, `some->`, `cond->` appear in almost every
   namespace — so modeling it is precisely where a taint engine risks inventing
   noise. Every form below is benign: any finding here is a false positive.

   This sample exists because the threading model could not be validated against
   a large real-world Clojure corpus, so the guard is a corpus one."
  (:require [clojure.string :as str]
            [clojure.java.shell :as shell]
            [clj-http.client :as client]))

;; Threading over CONSTANTS: no untrusted value anywhere in the chain.
(defn build-banner []
  (-> "  Report  "
      (str/trim)
      (str/upper-case)))

;; Threading a request value into pure data transforms that never reach a sink.
(defn summarize [req]
  (->> (:params req)
       (map str/trim)
       (remove str/blank?)
       (sort)
       (take 10)))

;; The tainted value is COERCED to a number before anything else; a parsed long
;; carries no injection metacharacters.
(defn fetch-page [req]
  (-> (:page req)
      (Long/parseLong)
      (max 1)
      (min 100)))

;; A constant command threaded into the shell sink — the sink fires only on a
;; TAINTED word, and nothing untrusted enters this chain.
(defn disk-usage []
  (-> ["df" "-h"]
      (->> (apply shell/sh))))

;; some-> short-circuits on nil; the threaded value is a literal config URL.
(defn ping-health []
  (some-> "https://status.internal.example/health"
          (client/get)))

;; cond-> threads a map through conditional assoc calls — data shaping only.
(defn describe [req verbose?]
  (cond-> {:ok true}
    verbose? (assoc :agent "nox")
    (:trace req) (assoc :traced true)))

;; A threading chain whose stages are all local pure helpers.
(defn normalize [s]
  (-> s
      (str/replace "\\" "/")
      (str/lower-case)
      (str/trim)))
