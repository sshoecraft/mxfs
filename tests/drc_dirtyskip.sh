#!/bin/bash
# drc_dirtyskip.sh (sess48 ccloop) — reboot-clean once, run 8/tcp dir_reuse with
# given modargs + reduced rounds, then pull the DECISIVE correlation:
#   P48-OWNEREVICT-DIRTYSKIP (stale-base survivor at handoff)  vs
#   mxfs-drc-RDMISS / CLASS (the durable single-dirent loss).
# Usage: tests/drc_dirtyskip.sh "<modargs>" [rounds]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
MODARGS="${1:-}"; ROUNDS="${2:-16}"; N="${3:-8}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
ALL="test1 test2 test3 test4 test5 test6 test7 test8"
NODES=$(echo $ALL | tr ' ' '\n' | head -n "$N" | tr '\n' ' ')
for d in $NODES; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
sleep 3
for d in $NODES; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
for t in $(seq 1 50); do
  ok=1; for n in $NODES; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done
  [ $ok = 1 ] && break; sleep 3
done
sleep 20
for n in $NODES; do timeout 8 $SSH $n $PASS "rm -f /root/drc_failrounds.txt; dmesg -C" >/dev/null 2>&1; done
echo "########## RUN modargs=[$MODARGS] rounds=$ROUNDS @ $(date -u +%T) ##########"
OUT=$(env MXFS_EXTRA_MODARGS="$MODARGS" MXFS_TEST_ENV="DRC_ROUNDS=$ROUNDS" ./run.sh "$N" tcp dir_reuse_coherency 2>&1)
echo "$OUT" | grep -E 'dir_reuse_coherency|converged|prep OK' | tail -3
echo "===== per-node correlation ====="
for n in $NODES; do
  echo "--- $n ---"
  timeout 12 $SSH $n $PASS "
    echo failrounds:; cat /root/drc_failrounds.txt 2>/dev/null | head -4
    echo P13=\$(dmesg|grep -c P13-COLLIDE) DIRTYSKIP=\$(dmesg|grep -c P48-OWNEREVICT-DIRTYSKIP) OWNEREVICT=\$(dmesg|grep -c P43-OWNEREVICT)
    echo dirtyskip-samples:; dmesg|grep -E 'P48-OWNEREVICT-DIRTYSKIP'|grep -oE 'daddr=[0-9-]+ dirty=[0-9] pin=[0-9] delwri=[0-9] done=[0-9] inail=[0-9]'|sort|uniq -c|tail -6
    echo rdmiss:; dmesg|grep -E 'mxfs-drc-RDMISS|mxfs-drc-CLASS'|tail -6
  " 2>/dev/null | grep -vE "^Warning:|^Unauthorized|^If you"
done
echo "########## done ##########"
