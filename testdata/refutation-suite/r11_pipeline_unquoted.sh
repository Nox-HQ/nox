#!/bin/bash
# Guards: sanitizer-pipeline-producer (TAINT-005; PR #585).
# nox-cover: sanitizer-pipeline-producer
#
# #585 taught the shell extractor that `jq`'s @sh filter shell-quotes what it
# emits, so a value read from such a pipeline is data by the time an `eval`
# re-parses it. That refutation is correct and it is class-precise: @sh clears
# the shell-parsing classes and leaves SSRF and path traversal alone.
#
# The bar is `jq` AND `@sh`, never the callee alone. This pipeline runs jq
# WITHOUT the filter, so every name arrives raw and the eval below is real code
# injection: a service named `; rm -rf /; echo ` runs.
#
# The wrong reasoning it catches is the generalization from the exact call that
# quotes to any call by the same name — the same step that would make `printf`
# a sanitizer because `printf %q` is one. That direction converts an entry that
# costs false positives into one that costs false NEGATIVES, which is the
# direction that hides real injections.
set -euo pipefail

kubectl get svc -o json | jq -r '.items[].metadata.name' | while read -r row; do
  eval "set -- $row"  # nox-expect: TAINT-005
done
