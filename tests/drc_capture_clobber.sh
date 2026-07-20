#!/bin/bash
# drc_capture_clobber.sh (sess49 ccloop 4cb2d0a2) — run 8-node dir_reuse ONCE and,
# on FAIL, capture the durable write-side dir-block CLOBBER mechanism from every
# node's dmesg into the SOURCE TREE (RULE 3: survives the reboot that wipes /tmp
# + node dmesg).  Targets the node1_f1..f26 first-data-block durable loss.
#
# Detectors greped: P62-DATAINIT-BLK0 (data_init zeroing a block holding node1_f1),
# P31E-DATAINIT-ABA / P32B-DOUBLEMAP (dir-block double-alloc / live-block re-init),
# P13-COLLIDE (intra-block slot collision), P11-DATALOG (node1_f1 -> daddr trace),
# P49-STALEBASE (in-core base missing durable peer dirent at modify).
#
# Usage: tests/drc_capture_clobber.sh [rounds] [N]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
ROUNDS="${1:-24}"; N="${2:-8}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
CAPDIR="$REPO/tests/_clobber_cap"; mkdir -p "$CAPDIR"
ALL="test1 test2 test3 test4 test5 test6 test7 test8"
NODES=$(echo $ALL | tr ' ' '\n' | head -n "$N" | tr '\n' ' ')
TS=$(date -u +%Y%m%dT%H%M%SZ)
for d in $NODES; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
sleep 3
for d in $NODES; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
for t in $(seq 1 50); do
  ok=1; for n in $NODES; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done
  [ $ok = 1 ] && break; sleep 3
done
sleep 20
echo "########## CLOBBER CAPTURE rounds=$ROUNDS N=$N ts=$TS @ $(date -u +%T) ##########"
# CLEAN timing (no instr/dirwr — they perturb the race into a heisenbug).
# P62-DATAINIT-BLK0, P13-COLLIDE, P49-STALEBASE are always-on for the storm dir.
OUT=$(env MXFS_TEST_ENV="DRC_ROUNDS=$ROUNDS" ./run.sh "$N" tcp dir_reuse_coherency 2>&1)
VERD=$(echo "$OUT" | grep -E 'nodes_pass=' | tail -1)
echo "VERDICT: $VERD"
if echo "$VERD" | grep -q "PASS  dir_reuse_coherency  (nodes_pass=$N/$N)"; then
  echo "PASS — no clobber to capture this run."
  exit 0
fi
echo "FAIL — capturing clobber signatures to $CAPDIR/clob_${TS}_*"
for n in $NODES; do
  timeout 25 $SSH $n $PASS "
    echo '### $n shutdown:'; dmesg|grep -c -iE 'Shutting down|ltbno|EFSCORRUPTED'
    echo '### P62-DATAINIT-BLK0 cached_has_n1f1=1:'; dmesg|grep 'P62-DATAINIT-BLK0'|grep 'cached_has_n1f1=1'|head -8
    echo '### P31E-DATAINIT-ABA live_dirents (>0):'; dmesg|grep 'P31E-DATAINIT-ABA'|grep -vE 'live_dirents=0 '|head -8
    echo '### P32B-DOUBLEMAP:'; dmesg|grep 'P32B-DOUBLEMAP'|head -6
    echo '### P13-COLLIDE:'; dmesg|grep 'P13-COLLIDE'|head -6
    echo '### P40-INCARN-ABA-DIRSKIP (false-positive suppress of live write?):'; dmesg|grep 'P40-INCARN-ABA-DIRSKIP'|head -8
    echo '### P49-STALEBASE:'; dmesg|grep 'P49-STALEBASE'|head -6
    echo '### P11-DATALOG node1_f1 (daddr trace):'; dmesg|grep 'P11-DATALOG'|grep -E 'name=\[node1_f1\]|name=\[node1_f1.md5\]'|head -8
  " 2>/dev/null | grep -vE "^Warning:|^Unauthorized|^If you" > "$CAPDIR/clob_${TS}_${n}.txt"
  echo "--- $n ---"; cat "$CAPDIR/clob_${TS}_${n}.txt"
done
echo "########## capture done @ $(date -u +%T) -> $CAPDIR ##########"
