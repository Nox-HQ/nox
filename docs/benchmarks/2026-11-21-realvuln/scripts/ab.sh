#!/bin/bash
# Re-scan listed repos with nox-fix into results-fix/, load-gated. Args: base dir, list.
B=$1; mkdir -p $B/results-fix
while read -r id; do
  o=$B/results-fix/$id; [ -f "$o/findings.json" ] && continue
  while [ "$(sysctl -n vm.loadavg | awk '{print int($2)}')" -ge 25 ]; do sleep 60; done
  mkdir -p $o
  perl -e 'alarm shift; exec @ARGV' 1800 $B/nox-fix scan "$B/repos/$id" --offline --format json --output "$o" </dev/null > "$o/stdout.log" 2>&1
  echo "$id rc=$?"
done < $2
