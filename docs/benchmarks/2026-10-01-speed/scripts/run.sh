#!/bin/bash
# Task 91: wall, CPU and peak memory per tool on the seven pinned repos.
# Each run waits for an idle machine (1-min load < 3) and records the load it
# started at. Two passes; the report takes the faster of the two per cell.
S=${BENCH_ROOT:?set BENCH_ROOT to a directory holding bench7/ and the nox binaries}
O=$S/speed91
NOX=${NOX:-nox}
waitidle() { while :; do l=$(sysctl -n vm.loadavg | awk '{print $2}'); awk -v l=$l 'BEGIN{exit !(l<3)}' && break; sleep 30; done; echo $l; }
run() { # tool repo pass cmd...
  t=$1; n=$2; p=$3; shift 3
  l=$(waitidle)
  /usr/bin/time -l "$@" >$O/$t-$n-$p.out 2>$O/$t-$n-$p.time </dev/null
  echo "$t $n $p load=$l $(awk '/ real/{r=$1;u=$3;s=$5} /maximum resident/{m=$1} END{printf "real=%s user=%s sys=%s rss_mb=%d", r,u,s,m/1048576}' $O/$t-$n-$p.time)" >> $O/results.txt
}
for p in 1 2; do
for r in $(find $S/bench7 -mindepth 1 -maxdepth 1 -type d | sort); do
  n=$(basename $r); cd $r
  run nox-offline $n $p $NOX scan . -offline -format json -output $O/noxoff-$n
  run nox-online  $n $p $NOX scan . -format json -output $O/noxon-$n
  run semgrep     $n $p semgrep scan --config p/default --json --metrics=off -q .
  run gitleaks    $n $p gitleaks dir . --report-format json --report-path $O/gl-$n.json --no-banner
  run trufflehog  $n $p trufflehog filesystem . --no-verification --no-update --json
done
done
echo DONE >> $O/results.txt
