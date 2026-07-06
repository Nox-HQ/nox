#!/bin/bash
# Honest false negatives: real vulnerabilities a correct scanner SHOULD flag but
# nox's flat, per-line shell recognizer cannot follow. These are annotated as
# ground truth so the corpus reports them as recall gaps (FN), never hidden.
# Shell has the lowest recall of any supported language precisely because of
# constructs like these — this file is the honest evidence of that.
set -euo pipefail

# FN: taint laundered through a `local`-declared variable inside a function. The
# recognizer skips `local` / `declare` / `export` / `readonly` lines (they are
# treated as structural), so the declared variable is never tainted and the sink
# below is missed. Modeling `local x="$1"` as a tainted assignment would close
# this, but distinguishing it from the many benign `local` uses without
# over-tainting is the open work.
launder_eval() {
  local arg="$1"
  eval "$arg" # nox-expect: TAINT-005
}

# FN: same laundering shape into a command-injection sink.
launder_exec() {
  local target="$2"
  bash -c "$target" # nox-expect: TAINT-002
}

launder_eval "$1"
launder_exec "$2"
