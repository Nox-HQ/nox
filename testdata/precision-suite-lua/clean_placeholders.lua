-- Clean: placeholder / example credentials. These are documentation defaults,
-- not real secrets — a scanner that flags them as hardcoded credentials is
-- producing a false positive. Mirrors the placeholder allowlist the other
-- language suites exercise.

local config = {
  api_key = "your-api-key-here",
  db_password = "changeme",
  smtp_password = "<your-smtp-password>",
  stripe_key = "sk_test_0000000000000000000000000",
  database_url = "postgres://USER:PASSWORD@localhost:5432/app",
}

-- os.getenv is the CORRECT way to read a secret at runtime; reading it is not a
-- vulnerability, and the fallback here is an obvious placeholder.
local token = os.getenv("API_TOKEN") or "REPLACE_ME_AT_DEPLOY_TIME"

return config, token
