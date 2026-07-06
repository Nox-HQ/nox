#!/bin/bash
# Code injection (CWE-95): a positional parameter / stdin value flows into
# `eval`, which re-parses its argument as shell code. Quoting the expansion does
# NOT help — eval executes the string either way — so a correct scanner fires
# TAINT-005.
set -euo pipefail

# Bare eval of a positional parameter.
expr="$1"
eval "$expr" # nox-expect: TAINT-005

# eval of a value read from stdin (the `read` builtin is a source).
read -r formula
eval "$formula" # nox-expect: TAINT-005
