#!/bin/bash
# Clean: placeholder / example credentials and config that must NOT be flagged as
# real secrets, plus command sinks quoted inside comments (prose, not code). A
# finding on any line here is a false positive.
set -euo pipefail

# Placeholder credentials — examples, not live secrets.
API_KEY="your-api-key-here"
DB_PASSWORD="changeme"
export DATABASE_URL="postgres://USER:PASSWORD@localhost:5432/dbname"
SMTP_PASS="<your-smtp-password>"

# The real secret comes from the environment at runtime, never hardcoded.
TOKEN="${DEPLOY_TOKEN:-}"

# Prose mentioning a dangerous idiom is a comment, not executable code:
#   eval "$USER_INPUT"      <- never do this
#   bash -c "$UNTRUSTED"    <- command injection
#   curl "$REMOTE_URL"      <- SSRF

echo "using key ${API_KEY} against ${DATABASE_URL}"
