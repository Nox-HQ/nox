#!/bin/bash
# A tainted value reaching a sink through a PIPELINE rather than as a literal
# argument of it. These were false negatives: the recognizer modelled only a
# command's OWN argument words, so a value arriving on stdin was invisible. The
# pipeline is now modelled — every upstream segment's reads flow down the pipe,
# and `xargs` hands them to the command it invokes as arguments.
set -euo pipefail

# The tainted value is piped into `xargs`, which invokes curl with it as an
# argument. An attacker controls which URLs are fetched.
fetch_all() {
  local urls="$1"
  echo "$urls" | xargs curl -fsSL # nox-expect: TAINT-006
}

# `xargs -I{}` builds a command STRING that interpolates a tainted positional
# parameter and hands it to `sh -c`: command injection, with the positional
# parameter used directly in the sink's argument (no intermediate assignment).
process_all() {
  find . -name '*.txt' -print0 | xargs -0 -I{} sh -c "process {} $1" # nox-expect: TAINT-002
}

# A bare `sh` at the end of a pipe executes its stdin as a script.
run_lines() {
  local script="$1"
  printf '%s\n' "$script" | sh # nox-expect: TAINT-002
}

fetch_all "$1"
process_all "$2"
run_lines "$3"
