#!/bin/bash
# Command injection (CWE-78): an untrusted value is executed as a command line
# via `bash -c` / `sh -c`, or interpolated unquoted into a command word. A
# correct scanner fires TAINT-002 on each.
set -euo pipefail

# sh -c "$user" runs the tainted string as a command line.
cmd="$1"
sh -c "$cmd" # nox-expect: TAINT-002

# bash -c with a positional parameter.
payload="$2"
bash -c "$payload" # nox-expect: TAINT-002

# A value read from stdin executed via bash -c.
read -r line
bash -c "$line" # nox-expect: TAINT-002
