#!/bin/bash
# Piped data that is DATA to the consumer, not the thing it executes or fetches.
set -euo pipefail

count_lines() {
  local input="$1"
  echo "$input" | wc -l
}

# `sh -c` with a FIXED script: stdin is read by `cat`, never executed.
show() {
  local text="$1"
  echo "$text" | sh -c 'cat'
}

# `xargs` invoking a non-sink.
remove_all() {
  local names="$1"
  echo "$names" | xargs echo
}

# `||` is the OR operator, not a pipe: the fixed script runs on failure.
ensure() {
  local path="$1"
  test -n "$path" || sh -c 'echo missing'
}

count_lines "$1"
show "$2"
remove_all "$3"
ensure "$4"
