#!/bin/bash
# Fetch each benchmark repo at its pinned commit. Args: base dir.
B=$1; mkdir -p $B/repos
while read -r id url sha lang; do
  d=$B/repos/$id
  if [ -d "$d/.git" ] && [ "$(git -C $d rev-parse HEAD 2>/dev/null)" = "$sha" ]; then continue; fi
  mkdir -p $d && git -C $d init -q 2>/dev/null
  git -C $d fetch -q --depth 1 "$url" "$sha" </dev/null && git -C $d -c advice.detachedHead=false checkout -q FETCH_HEAD </dev/null \
    && echo "ok $id" || echo "FAIL $id"
done < $B/repos.tsv
