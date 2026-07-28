#!/bin/bash
# Regression tests for two shapes that were DOCUMENTED as limits and are not.
# Both propagate today; the extractor comment and this suite's README claimed
# otherwise until each was checked by writing the sample and watching it pass.
#
# They are pinned here so the claim cannot drift back: a documented gap that does
# not exist is the same defect as an unguarded one, just in the other direction.
set -euo pipefail

# Array element carrying argv into a code-injection sink.
run_from_array() {
  local args=("$@")
  eval "${args[0]}" # nox-expect: TAINT-005
}

# A `${var//a/b}` substitution does not launder taint: the transformed value is
# still attacker-controlled, and reaches eval.
run_transformed() {
  local raw="$1"
  local clean="${raw//foo/bar}"
  eval "$clean" # nox-expect: TAINT-005
}

run_from_array "$@"
run_transformed "$1"
