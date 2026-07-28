#!/bin/bash
# Honest FALSE NEGATIVES: a tainted value reaching a sink through a PIPELINE
# rather than as a literal argument of it. Both are real vulnerabilities a
# correct scanner reports; nox does not, and they are annotated so the corpus
# scores the gap rather than staying silent about it.
#
# These were added deliberately to give this suite something to indict again: it
# had reached recall 1.0, at which point it could only detect regressions and
# could no longer say what the recognizer still cannot do. The way to raise the
# number is to close these, never to delete them.
set -euo pipefail

# FN: the tainted value is piped into `xargs`, which invokes curl with it as an
# argument. The recognizer models a command's OWN argument words; a value that
# arrives through the pipe is not one of them, so the curl call looks argument-
# less. An attacker controls which URLs are fetched.
fetch_all() {
  local urls="$1"
  echo "$urls" | xargs curl -fsSL # nox-expect: TAINT-006
}

# FN: `xargs -I{}` builds a command STRING that interpolates a tainted positional
# parameter and hands it to `sh -c`. The sink is real command injection, but the
# string is assembled as an argument of xargs rather than at an `sh -c` call the
# recognizer can attribute.
process_all() {
  find . -name '*.txt' -print0 | xargs -0 -I{} sh -c "process {} $1" # nox-expect: TAINT-002
}

fetch_all "$1"
process_all "$2"
