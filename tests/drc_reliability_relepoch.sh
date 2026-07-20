#!/bin/bash
# sess50: reliability loop for the relepoch cross-node clobber fix.
set -u
cd /src/mxfs
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
NODES="test1 test2 test3 test4 test5 test6 test7 test8"
RUNS="${1:-4}"; ROUNDS="${2:-16}"
pass=0; fail=0
for r in $(seq 1 $RUNS); do
  for d in $NODES; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
  sleep 3
  for d in $NODES; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
  for t in $(seq 1 50); do ok=1; for n in $NODES; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done; [ $ok = 1 ] && break; sleep 3; done
  sleep 20
  # clear stale per-VM failround logs so the verdict is unambiguous
  for n in $NODES; do timeout 8 $SSH $n $PASS "rm -f /root/drc_failrounds.txt" 2>/dev/null; done
  OUT=$(env MXFS_TEST_ENV="DRC_ROUNDS=$ROUNDS" ./run.sh 8 tcp dir_reuse_coherency 2>&1)
  V=$(echo "$OUT" | grep -E 'nodes_pass=' | tail -1)
  skips=0
  for n in $NODES; do c=$(timeout 10 $SSH $n $PASS "dmesg|grep -c P50-RELEPOCH-SKIP" 2>/dev/null | grep -oE '^[0-9]+'); skips=$((skips + ${c:-0})); done
  if echo "$V" | grep -q "nodes_pass=8/8"; then pass=$((pass+1)); st=PASS; else fail=$((fail+1)); st=FAIL; fi
  echo "RUN $r: $st  relepoch_skips=$skips  | $V"
done
echo "TALLY: PASS=$pass FAIL=$fail of $RUNS"
