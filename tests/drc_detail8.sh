#!/bin/bash
# drc_detail8.sh — 8/tcp dir_reuse single-iteration DETAILED mechanism capture
# (sess45 ccloop).  Runs clean-reboot iters until a FAIL, then pulls the DECISIVE
# mechanism discriminators from every node's fail snapshot:
#   P-DOUBLEGRANT / P-STALEMASTER-GRANT  -> split-brain (two EX masters)
#   P13-COLLIDE                          -> intra-block free-slot DOUBLE-ALLOC
#   P62-DATAINIT-BLK0 cached_has_n1f1=1  -> data_init ZEROED a live block0
#   P58-SELFSKIP-STALE-DIR               -> reload kept a stale base (dirty-keep)
#   P31E-DATAINIT-ABA / P61-BLK0         -> (instr only) dirty stale block0 RMW
#   drc-RDMISS                           -> which name(s) lost
# Pass modargs as $2 (e.g. "mxfs.instr=1 memb_settle_ms=20000 dir_modify_target_flush=1").
# Usage: tests/drc_detail8.sh <iters> [modargs]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
ITERS="${1:-4}"; MODARGS="${2:-}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
NODES="test1 test2 test3 test4 test5 test6 test7 test8"
reboot_clean() {
  for d in $NODES; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
  sleep 3
  for d in $NODES; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
  for t in $(seq 1 50); do
    ok=1; for n in $NODES; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done
    [ $ok = 1 ] && break; sleep 3
  done
  sleep 20
  # sess46: hung-task watchdog — dump the stack of any task in D-state >18s so a
  # wedged node's blocked op (the MASS-isolation root) lands in dmesg BEFORE the
  # 25s TCP_USER_TIMEOUT kills it.  panic_on_hung_task=0 (warn only, no reboot).
  for n in $NODES; do timeout 8 $SSH $n $PASS "sysctl -w kernel.hung_task_timeout_secs=18 kernel.hung_task_warnings=999999 kernel.hung_task_panic=0 >/dev/null 2>&1; rm -f /root/drc_failrounds.txt /root/drc_fail_r*.dmesg /root/drc_failverify_r*.dmesg /root/drc_create_r*.dmesg /dev/shm/drc_create_r*.dmesg; dmesg -C" >/dev/null 2>&1; done
}
for i in $(seq 1 "$ITERS"); do
  echo "########## ITER $i/$ITERS reboot @ $(date -u +%T) ##########"
  reboot_clean
  # sess47: wipe prior NFS streams + enable DRC_STREAM so EVERY node's live
  # dmesg (incl the hung-task wedge stack of a node that gets DECLARED DEAD and
  # never reaches a verify-snapshot) lands on the NFS export, surviving the death.
  rm -f /src/mxfs/tests/tcp/drc_cap/stream_rank*.log 2>/dev/null
  OUT=$(env MXFS_EXTRA_MODARGS="$MODARGS" MXFS_TEST_ENV="DRC_STREAM=1" ./run.sh 8 tcp dir_reuse_coherency 2>&1)
  res=$(echo "$OUT" | grep -E 'dir_reuse_coherency' | tail -1)
  echo "ITER $i: $res"
  echo "$res" | grep -q 'PASS' && continue
  echo "===== DETAIL CAPTURE iter $i ====="
  for n in $NODES; do
    echo "----- $n -----"
    timeout 25 $SSH $n $PASS '
      for F in /root/drc_fail_r*.dmesg /root/drc_failverify_r*.dmesg /root/drc_create_r*.dmesg /dev/shm/drc_create_r*.dmesg; do
        [ -f "$F" ] || continue
      done
      ALL="/root/drc_fail_r*.dmesg /root/drc_failverify_r*.dmesg /root/drc_create_r*.dmesg /dev/shm/drc_create_r*.dmesg"
      echo "[RDMISS]";        grep -hE "drc-RDMISS" $ALL 2>/dev/null | tail -2
      echo "[DOUBLEGRANT]";   grep -hE "P-DOUBLEGRANT" $ALL 2>/dev/null | tail -4
      echo "[STALEMASTER]";   grep -hE "P-STALEMASTER-GRANT" $ALL 2>/dev/null | tail -4
      echo "[P13-COLLIDE]";   grep -hE "P13-COLLIDE" $ALL 2>/dev/null | grep -oE "daddr=[0-9]+ off=[0-9]+ our=\[node[0-9a-z_.]*\].*ourdir=[0-9-]+" | tail -6
      RND=$(grep -hoE "round=[0-9]+" /root/drc_failrounds.txt 2>/dev/null | head -1 | cut -d= -f2)
      echo "[FAILROUND] R=$RND"
      echo "[P46-GROW failround newdbno->daddr (this node)]"
      CS=$(ls /root/drc_create_r${RND}_rank*.dmesg /dev/shm/drc_create_r${RND}_rank*.dmesg 2>/dev/null | head -1)
      if [ -n "$CS" ]; then
        sed -n "/DRCph r=$RND .*PHASE=create-start/,\$p" "$CS" 2>/dev/null | grep -oE "newdbno=[0-9]+ daddr=[0-9]+ incore_nx=[0-9]+" | sort | uniq -c | head -25
      fi
      echo "[MEMBERSHIP]";    grep -hoE "MXFS-MEMBERSHIP local=[0-9]+ active_count=[0-9]+" $ALL 2>/dev/null | sort -u | tail -8
      echo "[DEATH/FLAP]";    grep -hE "declared dead|SUSPECT|did not reconnect|self-fence|death.*grace|remaster|split" $ALL 2>/dev/null | tail -6
      echo "[HUNG-TASK wedge stack]"; grep -hA18 "blocked for more than" $ALL 2>/dev/null | grep -vE "^--$" | tail -40
      echo "[HUNG-TASK live now]"; ( echo w > /proc/sysrq-trigger 2>/dev/null; sleep 1; dmesg | grep -A14 "blocked for more than" | tail -40 )
    ' 2>/dev/null | grep -vE "^Warning:|^Unauthorized|^If you"
  done
  echo "===== NFS-STREAM hung-task wedge stacks (per rank, survives death) ====="
  for L in /src/mxfs/tests/tcp/drc_cap/stream_rank*.log; do
    [ -f "$L" ] || continue
    if grep -q "blocked for more than" "$L" 2>/dev/null; then
      echo "----- $L -----"
      grep -A20 "blocked for more than" "$L" 2>/dev/null | grep -vE "^--$" | tail -120
    fi
  done
  echo "===== NFS-STREAM death/membership timeline ====="
  for L in /src/mxfs/tests/tcp/drc_cap/stream_rank*.log; do
    [ -f "$L" ] || continue
    echo "----- $L -----"
    grep -hE "declaring dead|did not reconnect|SUSPECT|self-fence|declared dead|MXFS-MEMBERSHIP local" "$L" 2>/dev/null | tail -8
  done
  echo "===== END DETAIL CAPTURE iter $i ====="
done
echo "########## drc_detail8 done ##########"
