#!/bin/bash
# Run test_rename_visibility N times (instr=0) and report failures+wall per
# run, plus avg, to beat the high run-to-run variance.  Does NOT reset
# between runs (clears the test dir instead) — use tests/reset4.sh first.
# Usage: tests/measure_rename.sh [runs]
set -u
cd "$(dirname "$0")/.."
RUNS=${1:-3}
export MXFS_TESTS_DIR=/src/mxfs/tests MXFS_NODE_OFFSET=16
PASS=/tmp/.mxfs_pass; SSH=tools/mxfs_sshpass.sh
NODES="test1 test2 test3 test4"
tot=0
for r in $(seq 1 $RUNS); do
  for n in $NODES; do timeout 15 $SSH $n $PASS 'rm -rf /mnt/shared/.mxfs_test/rename_visibility 2>/dev/null' >/dev/null 2>&1 & done; wait
  t0=$(date +%s)
  out=$(timeout 120 tests/run_tests.sh --nodes 4 --phase cluster --test test_rename_visibility \
        --pass-file $PASS --device /dev/sda --mount-point /mnt/shared 2>&1)
  wall=$(($(date +%s)-t0))
  f=$(echo "$out" | grep -oE '[0-9]+ failure\(s\)' | grep -oE '^[0-9]+' | sort -rn | head -1)
  f=${f:-NA}
  sd=0; for n in $NODES; do timeout 8 $SSH $n $PASS 'dmesg|grep -qiE "Shutting down" && echo X' 2>/dev/null|grep -q X && sd=$((sd+1)); done
  echo "run $r: max_fails=$f wall=${wall}s shutdown_nodes=$sd"
  [ "$f" != "NA" ] && tot=$((tot+f))
done
echo "total_fails_sum=$tot over $RUNS runs"
