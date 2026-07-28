(ns app.clean-request-literals
  "Clean stressor: HAND-BUILT request/response maps. Every Clojure test suite,
   mock and benchmark constructs maps with Ring's own key names — `:headers`,
   `:body`, `:params`, `:uri`, `:query-string`. CONSTRUCTING such a map is not
   READING untrusted input, but a keyword is a source only in FUNCTION position
   (`(:headers req)`), never as a map key.

   Treating literal keys as source reads marked every fixture in a codebase as
   untrusted, which then flowed into any sink the value reached. This sample was
   added after exactly that was measured on real Clojure projects (reitit,
   compojure): 8 false positives, all on hand-built maps in tests. Any finding
   here is a false positive."
  (:require [clojure.java.io :as io]))

;; A response fixture — the shape compojure's own tests use.
(def expected-response
  {:status  200
   :headers {"Content-Type" "text/html; charset=utf-8"}
   :body    "<h1>Foo</h1>"})

;; A mock request threaded into a handler and read back — the shape reitit's
;; benchmarks use. `slurp` here consumes a response stream, not a path.
(defn exercise [app]
  (let [request {:request-method :post
                 :uri            "/plus"
                 :headers        {"content-type" "application/json"}
                 :body           "{\"x\":1,\"y\":2}"}]
    (-> request app :body slurp)))

;; Threading a literal map through pure data shaping.
(defn describe []
  (-> {:params {:x 1} :query-string "x=1"}
      (assoc :checked true)
      (dissoc :query-string)))

;; A vector literal holding Ring-ish keywords as DATA.
(def tracked-keys [:headers :body :params :uri])

;; Reading a fixture file by a constant path is not traversal.
(defn load-fixture []
  (slurp (io/resource "fixtures/sample.json")))
