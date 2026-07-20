#!/bin/bash
# drc_batch8.sh — 8/tcp dir_reuse_coherency reliability batch (sess45 ccloop).
# Runs ITERS clean-reboot iterations, NEVER breaks, classifies each result:
#   PASS | FLAP (TCP false-death/split-brain) | SINGLE (1-dirent loss) | MASS (>1)
# Prints a summary distribution at the end so the dominant 8-node failure mode
# is visible.  Pulls the failing-round RDMISS + flap/STALEMASTER signatures.
# Usage: tests/drc_batch8.sh <iters> [modargs]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
ITERS="${1:-5}"; MODARGS="${2:-}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
NODES="test1 test2 test3 test4 test5 test6 test7 test8"
np=0; nflap=0; nsingle=0; nmass=0; nother=0
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
echo "=== drc_batch8 ITERS=$ITERS MODARGS=[$MODARGS] build=$(modinfo mxfs.ko|awk '/srcversion/{print $2}') @ $(date -u +%T) ==="
for i in $(seq 1 "$ITERS"); do
  echo "########## ITER $i/$ITERS reboot @ $(date -u +%T) ##########"
  reboot_clean
  OUT=$(env MXFS_EXTRA_MODARGS="$MODARGS" ./run.sh 8 tcp dir_reuse_coherency 2>&1)
  res=$(echo "$OUT" | grep -E 'dir_reuse_coherency' | tail -1)
  if echo "$res" | grep -q 'PASS'; then
    np=$((np+1)); echo "ITER $i: PASS"; continue
  fi
  # FAIL — pull diagnostics from rank1 (representative) + check for flap on any node
  flap=0; miss=""; nmiss=0
  for n in $NODES; do
    f=$(timeout 12 $SSH $n $PASS '
      FR=$(ls -1 /root/drc_fail_r*.dmesg 2>/dev/null | head -1)
      [ -z "$FR" ] && FR=$(ls -1 /root/drc_failverify_r*.dmesg 2>/dev/null | head -1)
      [ -n "$FR" ] && grep -hE "did not reconnect within|drc-RDMISS" "$FR" 2>/dev/null | head -3
    ' 2>/dev/null | grep -vE '^Warning:|^Unauthorized|^If you')
    echo "$f" | grep -q "did not reconnect within" && flap=1
    if [ -z "$miss" ]; then
      m=$(echo "$f" | grep -oE 'missing_from_readdir=\[[^]]*\]' | head -1)
      [ -n "$m" ] && { miss="$m"; nmiss=$(echo "$m" | grep -oE 'node[0-9]+_[a-z0-9._]+' | grep -c .); }
    fi
  done
  if [ "$flap" = 1 ]; then
    nflap=$((nflap+1)); echo "ITER $i: FAIL/FLAP miss=$miss"
  elif [ "$nmiss" = 1 ]; then
    nsingle=$((nsingle+1)); echo "ITER $i: FAIL/SINGLE miss=$miss"
  elif [ "$nmiss" -gt 1 ] 2>/dev/null; then
    nmass=$((nmass+1)); echo "ITER $i: FAIL/MASS($nmiss) miss=$miss"
  else
    nother=$((nother+1)); echo "ITER $i: FAIL/OTHER res=[$res] miss=[$miss]"
  fi
done
echo "########## drc_batch8 SUMMARY: PASS=$np FLAP=$nflap SINGLE=$nsingle MASS=$nmass OTHER=$nother / $ITERS ##########"
echo "########## drc_batch8 done ##########"
