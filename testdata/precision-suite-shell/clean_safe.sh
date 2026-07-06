#!/bin/bash
# Clean: the SAFE counterparts of the tp_*.sh flows. None of these should fire —
# each routes the tainted value through the sanitizer / safe form that
# neutralizes its sink's vuln class, or uses the value only in a non-sink
# position. A finding on any line here is a false positive.
set -euo pipefail

# printf %q quotes a value safely before it is eval'd.
raw="$1"
safe="$(printf '%q' "$raw")"
eval "$safe"

# basename strips directory components, defusing path traversal before source.
name="$2"
base="$(basename "$name")"
source "/etc/app/plugins/$base"

# A quoted expansion passed to a NORMAL command (not a sink) is safe — no word
# splitting, and cp is not a shell interpreter.
src="$3"
cp "$src" /backup/

# Running a STATIC script file with bash (no -c) is not command injection; the
# script path is a constant, not a tainted string executed as a command line.
bash /opt/deploy/run.sh

# A constant command string is never tainted.
eval "echo done"

# Integer-context arithmetic strips every injection metacharacter: $((...))
# coerces the value to a number, so the result is safe to use.
count=$(( $4 + 0 ))
echo "processed $count items"
