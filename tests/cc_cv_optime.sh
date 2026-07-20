#!/bin/bash
# cc_cv_optime.sh — reproduce cache_coherency's cv phase shape at N nodes with
# PER-OP microsecond timing (sess6 ccloop 72513a13: cv-verify 360ms/op at 32
# nodes vs 7ms isolated — storm amplification hunt).
#
# Phase 1: every node writes its own file + sync (timed).
# Phase 2: barrier via sleep-sync (parent orchestrates), then every node
#          test-f + cats ALL N files, each op timed.
# Output: per-node phase walls + per-op latencies, slowest ops named.
#
# Usage: tests/cc_cv_optime.sh [N=32]
set -u
cd "$(dirname "$0")/.."
PASS=/tmp/.mxfs_pass; SSH=tools/mxfs_sshpass.sh
N=${1:-32}
D=/mnt/shared/.cc_cv_optime
OUT=/tmp/cc_cv_optime; rm -rf $OUT; mkdir -p $OUT

timeout 20 $SSH test1 $PASS "rm -rf $D; mkdir -p $D; sync" >/dev/null 2>&1
echo "== phase 1: $N concurrent write+sync =="
for r in $(seq 1 $N); do
  ( timeout 60 $SSH test$r $PASS '
      t0=${EPOCHREALTIME/./}
      echo "hello from node '$r'" > '$D'/node'$r'.txt
      t1=${EPOCHREALTIME/./}
      sync
      t2=${EPOCHREALTIME/./}
      echo "W'$r' create=$(( (t1-t0)/1000 ))ms sync=$(( (t2-t1)/1000 ))ms"' 2>&1 | grep "^W" > $OUT/w$r ) &
done
wait
cat $OUT/w* | sort -t= -k3 -n | tail -5
awk -F'[= ]' '{gsub("ms","");c+=$3;s+=$5} END{printf "sum create=%dms sum sync=%dms\n", c, s}' $OUT/w*
echo "== phase 2: $N concurrent full-dir read storms =="
for r in $(seq 1 $N); do
  ( timeout 120 $SSH test$r $PASS '
      t0=${EPOCHREALTIME/./}
      for n in $(seq 1 '$N'); do
        f='$D'/node${n}.txt
        ta=${EPOCHREALTIME/./}
        test -f $f && cat $f > /dev/null
        tb=${EPOCHREALTIME/./}
        echo "R'$r' n=$n $(( (tb-ta)/1000 ))ms"
      done
      t1=${EPOCHREALTIME/./}
      echo "T'$r' total=$(( (t1-t0)/1000 ))ms"' 2>&1 | grep -E "^[RT]" > $OUT/r$r ) &
done
wait
grep -h "^T" $OUT/r* | sort -t= -k2 -n | tail -3
echo "-- per-op distribution (ms):"
grep -h "^R" $OUT/r* | awk '{gsub("ms","");print $3}' | sort -n | awk '{v[NR]=$1} END{printf "n=%d p50=%d p90=%d p99=%d max=%d\n", NR, v[int(NR*.5)], v[int(NR*.9)], v[int(NR*.99)], v[NR]}'
echo "-- slowest 10 ops (reader file ms):"
grep -h "^R" $OUT/r* | awk '{gsub("ms","");print}' | sort -k3 -n | tail -10
timeout 20 $SSH test1 $PASS "rm -rf $D; sync" >/dev/null 2>&1
