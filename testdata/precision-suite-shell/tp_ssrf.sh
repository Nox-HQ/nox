#!/bin/bash
# SSRF (CWE-918): a tainted URL is fetched with curl/wget. Unlike command
# injection, quoting the expansion does not help — the request still goes to the
# attacker-chosen host — so a correct scanner fires TAINT-006 either way.
set -euo pipefail

# curl of a tainted URL (quoted).
url="$1"
curl "$url" # nox-expect: TAINT-006

# wget of a tainted URL sourced from the CGI query string.
target="$QUERY_STRING"
wget "$target" # nox-expect: TAINT-006
