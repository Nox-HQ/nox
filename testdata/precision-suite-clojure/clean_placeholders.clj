(ns app.placeholders
  "Clean: placeholder / example credentials and env-var reads. These deliberately
   contain secret-shaped strings that must NOT be flagged (they are placeholders
   or come from the environment, not hardcoded live secrets). Any finding here is
   a false positive.")

;; Placeholder credentials — the example/placeholder allowlist must drop these.
(def config
  {:api-key   "your-api-key-here"
   :password  "changeme"
   :db-url    "postgres://USER:PASSWORD@localhost:5432/app"
   :smtp-pass "<your-smtp-password>"
   :token     "sk_test_00000000000000000000000000"})

;; Secrets pulled from the environment are not hardcoded.
(def runtime-key (System/getenv "APP_API_KEY"))
(def runtime-db  (System/getenv "DATABASE_URL"))
