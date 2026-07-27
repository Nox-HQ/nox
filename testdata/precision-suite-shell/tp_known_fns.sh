#!/bin/bash
# Taint laundered through a `local`-declared variable inside a function. These
# were honest false negatives until declaration-with-initializer lines were
# recognized as the assignments they are; they are kept as the regression test
# for that flow.
set -euo pipefail

# `local arg="$1"` initializes as well as declares, so the keyword is blanked and
# the assignment underneath is read normally — arg carries the argv taint into
# eval. A BARE `local a b c` still skips: it carries no dataflow.
launder_eval() {
  local arg="$1"
  eval "$arg" # nox-expect: TAINT-005
}

# The same laundering shape into a command-injection sink.
launder_exec() {
  local target="$2"
  bash -c "$target" # nox-expect: TAINT-002
}

launder_eval "$1"
launder_exec "$2"
