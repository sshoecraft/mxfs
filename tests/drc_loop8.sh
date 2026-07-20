#!/bin/bash
# drc_loop8.sh — run the 8/tcp dir_reuse_coherency criterion N times with a clean
# reboot between each, recording PASS/FAIL per iteration.  Measures the
# intermittent-loss rate and validates a fix toward 100%.
# Usage: tests/drc_loop8.sh <iters> [modargs]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
ITERS="${1:-5}"; MODARGS="${2:-}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
NODES="test1 test2 test3 test4 test5 test6 test7 test8"
reboot_clean() {
  for d in $NODES; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
  sleep 3
  for d in $NODES; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
  # wait for ssh on all nodes
  for t in $(seq 1 50); do
    ok=1
    for n in $NODES; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done
    [ $ok = 1 ] && break
    sleep 3
  done
  sleep 20   # generous settle: let iSCSI/network/discovery quiesce before mxfs forms
  # clear per-node state so failrounds + dmesg reflect THIS iter only
  for n in $NODES; do timeout 8 $SSH $n $PASS "rm -f /root/drc_failrounds.txt; dmesg -C" >/dev/null 2>&1; done
}
PASSC=0; FAILC=0
for i in $(seq 1 "$ITERS"); do
  echo "########## ITER $i/$ITERS reboot @ $(date -u +%T) ##########"
  reboot_clean
  OUT=$(env MXFS_EXTRA_MODARGS="$MODARGS" ./run.sh 8 tcp dir_reuse_coherency 2>&1)
  res=$(echo "$OUT" | grep -E 'dir_reuse_coherency' | tail -1)
  echo "ITER $i: $res"
  # always snapshot membership-churn counts (even on PASS)
  printf "  churn:"
  for n in $NODES; do
    c=$(timeout 8 $SSH $n $PASS "echo -n disc=; dmesg|grep -c 'TCP peer.*disconnected'; echo -n ' defer=; '; dmesg|grep -c 'deferring death'; echo -n ' declared=; '; dmesg|grep -c 'declaring dead'; echo -n ' cancel=; '; dmesg|grep -c 'cancelling pending'; echo -n ' stale=; '; dmesg|grep -c 'P-STALEMASTER-GRANT'" 2>/dev/null | tr '\n' ' ')
    printf " [%s %s]" "$n" "$c"
  done; echo
  if echo "$res" | grep -q 'PASS'; then PASSC=$((PASSC+1));
  else
    FAILC=$((FAILC+1))
    echo "$OUT" | tail -15
    for n in $NODES; do
      echo "--- $n fail evidence ---"
      timeout 14 $SSH $n $PASS "cat /root/drc_failrounds.txt 2>/dev/null | head -5; echo '--- declared/stale ---'; dmesg|grep -E 'declaring dead|P-STALEMASTER-GRANT'|tail -8; echo '--- relverify-mismatch ---'; dmesg|grep -E 'P25-RELVERIFY-MISMATCH'|tail -8; echo '--- dataclobber ---'; dmesg|grep -E 'P-DATACLOBBER-SKIP'|tail -8; echo '--- shutdown ---'; dmesg|grep -iE 'Internal error|force shutdown|has been shut down|Corruption|EFSCORRUPTED|EFSBADCRC|bad CRC'|tail -6" 2>/dev/null
    done
  fi
done
echo "########## SUMMARY: PASS=$PASSC FAIL=$FAILC of $ITERS ##########"
