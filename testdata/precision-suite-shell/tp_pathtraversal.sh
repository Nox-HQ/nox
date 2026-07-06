#!/bin/bash
# Path traversal (CWE-22): a request/argument-controlled path is `source`d (or
# loaded via the `.` builtin), executing an attacker-chosen script. Quoting does
# not stop traversal, so a correct scanner fires TAINT-004.
set -euo pipefail

# Sourcing a tainted configuration path.
cfg="$1"
source "$cfg" # nox-expect: TAINT-004

# The `.` builtin is `source`; a tainted path loads an attacker script.
plugin="$2"
. "$plugin" # nox-expect: TAINT-004
