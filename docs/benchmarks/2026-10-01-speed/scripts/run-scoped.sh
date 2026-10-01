#!/bin/bash
S=${BENCH_ROOT:?set BENCH_ROOT to a directory holding bench7/ and the nox binaries}
O=$S/speed91
NOX=${NOX:-nox}
waitidle() { while :; do l=$(sysctl -n vm.loadavg | awk '{print $2}'); awk -v l=$l 'BEGIN{exit !(l<3)}' && break; sleep 30; done; echo $l; }
run() {
  t=$1; n=$2; p=$3; shift 3
  l=$(waitidle)
  /usr/bin/time -l "$@" >$O/$t-$n-$p.out 2>$O/$t-$n-$p.time </dev/null
  echo "$t $n $p load=$l $(awk '/ real/{r=$1;u=$3;s=$5} /maximum resident/{m=$1} END{printf "real=%s user=%s sys=%s rss_mb=%d", r,u,s,m/1048576}' $O/$t-$n-$p.time)" >> $O/results-scoped.txt
}
for p in 1 2; do
for r in $(find $S/bench7 -mindepth 1 -maxdepth 1 -type d | sort); do
  n=$(basename $r); cd $r
  run nox-full    $n $p $NOX scan . -offline -format json -output $O/s-full-$n
  run nox-secrets $n $p $NOX scan . -offline -only secrets -format json -output $O/s-sec-$n
  run nox-code    $n $p $NOX scan . -offline -only code -format json -output $O/s-code-$n
  run nox-deps    $n $p $NOX scan . -only deps -format json -output $O/s-deps-$n
done
done
echo DONE >> $O/results-scoped.txt
