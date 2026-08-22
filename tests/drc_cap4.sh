#!/bin/bash
# drc_cap4.sh — 4/tcp dir_reuse_coherency capture loop (sess45 ccloop).
# Adapted from drc_cap8.sh.  On a FAIL pulls the DECISIVE materialization
# detectors that are ALWAYS-ON in the build:
#   - mxfs-drc-RDMISS / drc-FAIL  (which expected name is absent)
#   - P62-DATAINIT-BLK0           (data_init zeroing logical block0; cached_has_n1f1)
#   - P68-DATAINIT                (data_init at ANY block; in-core vs disk nextents)
#   - P31E/P31F (only if mxfs.instr=1 passed in MODARGS)
# Correlates the FAILING round's create-snapshot too (block0 materialization
# happens during the create wave, BEFORE the verify snapshot).
# Usage: tests/drc_cap4.sh <iters> [modargs]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
ITERS="${1:-6}"; MODARGS="${2:-}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
NODES="test1 test2 test3 test4"
reboot_clean() {
  for d in $NODES; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
  sleep 3
  for d in $NODES; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
  for t in $(seq 1 50); do
    ok=1
    for n in $NODES; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done
    [ $ok = 1 ] && break
    sleep 3
  done
  sleep 20
  for n in $NODES; do timeout 8 $SSH $n $PASS "rm -f /root/drc_failrounds.txt /root/drc_fail_r*.dmesg /root/drc_failverify_r*.dmesg /root/drc_create_r*.dmesg /dev/shm/drc_create_r*.dmesg; dmesg -C" >/dev/null 2>&1; done
}
for i in $(seq 1 "$ITERS"); do
  echo "########## ITER $i/$ITERS reboot @ $(date -u +%T) ##########"
  reboot_clean
  OUT=$(env MXFS_EXTRA_MODARGS="$MODARGS" ./run.sh 4 tcp dir_reuse_coherency 2>&1)
  res=$(echo "$OUT" | grep -E 'dir_reuse_coherency' | tail -1)
  echo "ITER $i: $res"
  if echo "$res" | grep -q 'PASS'; then continue; fi
  echo "===== FAIL CAPTURE iter $i ====="
  # find the failing round number from any node
  FRND=""
  for n in $NODES; do
    r=$(timeout 10 $SSH $n $PASS 'head -1 /root/drc_failrounds.txt 2>/dev/null' 2>/dev/null | grep -oE 'round=[0-9]+' | head -1 | cut -d= -f2)
    [ -n "$r" ] && { FRND="$r"; break; }
  done
  echo "FAILING ROUND = ${FRND:-unknown}"
  for n in $NODES; do
    echo "----- $n -----"
    timeout 25 $SSH $n $PASS "
      echo '[failrounds]'; head -4 /root/drc_failrounds.txt 2>/dev/null
      FV=\$(ls -1 /root/drc_failverify_r*.dmesg 2>/dev/null | head -1)
      FF=\$(ls -1 /root/drc_fail_r*.dmesg 2>/dev/null | head -1)
      CR="/root/drc_create_r${FRND}_rank*.dmesg /dev/shm/drc_create_r${FRND}_rank*.dmesg"
      echo '[RDMISS/CLASS/FAIL in verify snapshot \$FV]'
      [ -n \"\$FV\" ] && grep -E 'drc-RDMISS|drc-CLASS|drc-FAIL' \"\$FV\" | tail -8
      echo '[P62-DATAINIT-BLK0 cached_has_n1f1=1 (the clobber) — verify+create]'
      grep -hE 'P62-DATAINIT-BLK0' \$FV \$FF \$CR 2>/dev/null | grep 'cached_has_n1f1=1' | tail -12
      echo '[P62-DATAINIT-BLK0 all — last 8]'
      grep -hE 'P62-DATAINIT-BLK0' \$FV \$FF \$CR 2>/dev/null | tail -8
      echo '[P68-DATAINIT — last 10]'
      grep -hE 'P68-DATAINIT' \$FV \$FF \$CR 2>/dev/null | tail -10
      echo '[P31E/P31F (instr only)]'
      grep -hE 'P31E-DATAINIT-ABA|P31F-BMAP' \$FV \$FF \$CR 2>/dev/null | tail -6
      echo '[DOUBLEGRANT/STALEMASTER]'
      grep -hE 'MX-DOUBLEGRANT|P-STALEMASTER-GRANT' \$FV \$FF \$CR 2>/dev/null | tail -6
    " 2>/dev/null | grep -vE '^Warning:|^Unauthorized|^If you'
  done
  echo "===== END FAIL CAPTURE ====="
  break
done
echo "########## drc_cap4 done ##########"
