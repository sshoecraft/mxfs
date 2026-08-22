#!/bin/bash
# drc_cap8.sh — 8/tcp dir_reuse_coherency capture loop that, on a FAIL, pulls
# the DECISIVE diagnostics from each node BEFORE the next reboot wipes them:
#   - mxfs-drc-RDMISS  (which expected name is absent from readdir)
#   - mxfs-drc-CLASS   (LOOKUP_OK = enumeration/leaf-data divergence;
#                       LOOKUP_ENOENT = durable data-block loss; REREAD_*)
#   - the failure-moment dmesg snapshot grepped for the lost-block signatures
#     (P-DATACLOBBER / P25-RELVERIFY / P60-BMBT / DABUF_MAP_HOLE / leaf / bmbt)
# Loops until a FAIL is captured or ITERS exhausted.
# Usage: tests/drc_cap8.sh <iters> [modargs]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
ITERS="${1:-6}"; MODARGS="${2:-}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
NODES="test1 test2 test3 test4 test5 test6 test7 test8"
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
  for n in $NODES; do timeout 8 $SSH $n $PASS "rm -f /root/drc_failrounds.txt /root/drc_fail_r*.dmesg /root/drc_failverify_r*.dmesg; dmesg -C" >/dev/null 2>&1; done
}
for i in $(seq 1 "$ITERS"); do
  echo "########## ITER $i/$ITERS reboot @ $(date -u +%T) ##########"
  reboot_clean
  OUT=$(env MXFS_EXTRA_MODARGS="$MODARGS" ./run.sh 8 tcp dir_reuse_coherency 2>&1)
  res=$(echo "$OUT" | grep -E 'dir_reuse_coherency' | tail -1)
  echo "ITER $i: $res"
  if echo "$res" | grep -q 'PASS'; then continue; fi
  echo "===== FAIL CAPTURE iter $i ====="
  for n in $NODES; do
    echo "----- $n -----"
    timeout 20 $SSH $n $PASS '
      echo "[failrounds]"; head -3 /root/drc_failrounds.txt 2>/dev/null
      FR=$(ls -1 /root/drc_fail_r*.dmesg 2>/dev/null | head -1)
      [ -z "$FR" ] && FR=$(ls -1 /root/drc_failverify_r*.dmesg 2>/dev/null | head -1)
      echo "[snapshot=$FR]"
      if [ -n "$FR" ]; then
        echo "[RDMISS/CLASS]"; grep -E "drc-RDMISS|drc-CLASS|drc-DIRID|drc-FAIL" "$FR" | tail -12
        echo "[flap events (deferring/reconnect/declare/timeout)]"; grep -E "deferring death|reconnected — cancelling|did not reconnect|declaring dead|timed out \(slow peer|communication with node" "$FR" | tail -12
        echo "[COUNTREGRESS — fail+create snapshots]"; grep -hE "P-COUNTREGRESS" /root/drc_fail_r*.dmesg /root/drc_create_r*.dmesg /dev/shm/drc_create_r*.dmesg 2>/dev/null | tail -12
        echo "[DOUBLEGRANT / STALEMASTER (serialization breaks) — all snapshots]"; grep -hE "MX-DOUBLEGRANT|P-STALEMASTER-GRANT" /root/drc_fail_r*.dmesg /root/drc_create_r*.dmesg /dev/shm/drc_create_r*.dmesg 2>/dev/null | tail -16
        echo "[clobber/relverify/bmbt/hole/barrier]"; grep -E "P-DATACLOBBER-SKIP|P25-RELVERIFY|P60-BMBT|DABUF_MAP_HOLE|P39-EXSUBSET|P26-SUBSET|P40-WRBARRIER" "$FR" | tail -12
        echo "[P40 max waits across whole dmesg]"; grep -E "P40-WRBARRIER" "$FR" | grep -oE "waited=[0-9]+ms inflight=[0-9]+" | sort -t= -k2 -n | tail -6
        mkdir -p /src/mxfs/tests/tcp/drc_cap 2>/dev/null; grep -E "P-DLAND" "$FR" > "/src/mxfs/tests/tcp/drc_cap/dland_$(hostname).txt" 2>/dev/null; echo "[P-DLAND ring dump -> dland_$(hostname).txt lines=$(grep -cE P-DLAND "$FR")]"
      fi
    ' 2>/dev/null | grep -vE '^Warning:|^Unauthorized|^If you'
  done
  echo "===== END FAIL CAPTURE ====="
  break
done
echo "########## drc_cap8 done ##########"
