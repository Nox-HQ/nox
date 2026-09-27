#!/bin/zsh
# Head-to-head: every tool over the same seven pinned checkouts.
# Usage: CORPUS=<dir> [WORK=<dir>] [NOX=<nox binary>] run.sh <tool> [repo...]
#   tool: nox gitleaks trufflehog osv trivy semgrep
set -u
H=${WORK:-$PWD}
C=${CORPUS:?set CORPUS to the directory of pinned checkouts}
NOX=${NOX:-nox}
tool=$1; shift
repos=(${@:-$(ls $C)})
mkdir -p $H/out/$tool $H/time/$tool
for r in $repos; do
  src=$C/$r
  o=$H/out/$tool/$r
  t=$H/time/$tool/$r.txt
  print "== $tool $r $(date +%T)"
  case $tool in
    nox)        cmd=($NOX scan $src --format json --output $o) ;;
    gitleaks)   cmd=(/opt/homebrew/bin/gitleaks dir $src --report-format json --report-path $o.json --no-banner --exit-code 0 --log-level error) ;;
    trufflehog) cmd=(sh -c "trufflehog filesystem '$src' --json --no-verification --no-update > '$o.jsonl' 2>'$o.err'") ;;
    osv)        cmd=(sh -c "osv-scanner scan source -r '$src' --format json > '$o.json' 2>'$o.err'; true") ;;
    trivy)      cmd=(trivy fs --scanners vuln --format json --output $o.json --quiet $src) ;;
    semgrep)    cmd=(semgrep scan --config p/default --json --metrics=off --quiet --output $o.json $src) ;;
  esac
  /usr/bin/time -l $cmd >/dev/null 2>$t
  print "   rc=$? $(grep -E 'real|maximum resident' $t | tr -s ' ' | tr '\n' ' ')"
done
