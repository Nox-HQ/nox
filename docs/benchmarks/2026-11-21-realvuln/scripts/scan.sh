#!/bin/bash
# Scan each benchmark repo with nox, offline, one at a time, only while the
# 1-minute load is under 25. Args: base dir.
B=$1; mkdir -p $B/results
while read -r id url sha lang; do
  o=$B/results/$id
  [ -f "$o/findings.json" ] && continue
  [ -d "$B/repos/$id/.git" ] || { echo "NOREPO $id"; continue; }
  while :; do
    l=$(sysctl -n vm.loadavg | awk '{print int($2)}')
    [ "$l" -lt 25 ] && break
    sleep 60
  done
  mkdir -p $o
  s=$(date +%s)
  perl -e 'alarm shift; exec @ARGV' 1800 $B/nox scan "$B/repos/$id" --offline --format json --output "$o" </dev/null > "$o/stdout.log" 2>&1
  echo "$id rc=$? $(( $(date +%s) - s ))s"
done < $B/repos.tsv
