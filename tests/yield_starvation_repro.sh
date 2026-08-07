#!/bin/bash
# yield_starvation_repro.sh — deterministic exposure of D-CAW-YIELD-STARVATION-SHUTDOWN
#
# Mechanism under test (sess31, ccloop c7ee71c6): a mode-compatible fresh INODE
# acquire that defers to yield_to without registering in `waiters` is invisible
# to the ticket releases rebuild (yield_to = waiters).  Under sustained PR
# churn + EX writers on ONE shared directory, the deferrer can burn all 100
# CAW retries (P-CAWEXH yield_bo=100), the acquire returns -ETIMEDOUT, and
# mxfs_dlm_ilock_begin force-shuts-down the filesystem.
#
# This harness makes that regime on demand:
#   - every node runs a PR antagonist (ls -f + stat loop on the shared dir)
#   - every node runs an EX writer (mkdir/rmdir churn in the same dir)
#   - for DURATION seconds; then we count NEW-format P-CAWEXH (yreg= field,
#     0.11.269+) and FS shutdowns cluster-wide since the phase marker.
#
# Usage: tests/yield_starvation_repro.sh <nnodes> [duration_s] [arm]
#   arm: "fix" (caw_fresh_register=1) | "control" (=0) | "asis" (leave knobs)
# Exit: 0 = no exhaustion & no shutdown; 10 = exhaustion(s); 20 = shutdown(s).
#
# RULE 0 budget: DURATION + ~45s fan-out/harvest overhead.

set -u
cd "$(dirname "$0")/.."
N=${1:?nnodes}
DUR=${2:-60}
ARM=${3:-asis}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
TAG="ysr_$(date +%s)"

case "$ARM" in
  fix)     REG=1;;
  control) REG=0;;
  asis)    REG=-1;;
  *) echo "bad arm: $ARM"; exit 2;;
esac

echo "== yield_starvation_repro N=$N dur=${DUR}s arm=$ARM tag=$TAG"

# knobs + phase marker (dmesg marker scopes the harvest window per node)
for i in $(seq 1 "$N"); do
  (
    if [ "$REG" -ge 0 ]; then
      timeout 12 $SSH test$i "echo $REG > /sys/module/mxfs/parameters/caw_fresh_register" </dev/null >/dev/null 2>&1
    fi
    timeout 12 $SSH test$i "echo \"MXFS_YSR_MARK $TAG\" > /dev/kmsg; mkdir -p $MNT/ysr" </dev/null >/dev/null 2>&1
  ) &
done
wait

# storm: PR antagonists + fsyncing EX writers on a GROWING shared dir (the
# dirent_durability shape: fsync stretches EX tenures; growth stretches
# readdir PR holds), phase-aligned so all nodes press simultaneously.
START=$(( $(date +%s) + 6 ))
for i in $(seq 1 "$N"); do
  (
    timeout $((DUR+35)) $SSH test$i "
      while [ \$(date +%s) -lt $START ]; do sleep 0.2; done
      end=\$(( $START + $DUR ))
      ( while [ \$(date +%s) -lt \$end ]; do ls -f $MNT/ysr >/dev/null 2>&1; stat $MNT/ysr >/dev/null 2>&1; done ) &
      ( while [ \$(date +%s) -lt \$end ]; do ls -f $MNT/ysr >/dev/null 2>&1; done ) &
      ( k=0; while [ \$(date +%s) -lt \$end ]; do k=\$((k+1)); mkdir $MNT/ysr/n${i}_\$k >/dev/null 2>&1; done ) &
      ( exec 9<$MNT/ysr 2>/dev/null; while [ \$(date +%s) -lt \$end ]; do sync -f $MNT/ysr 2>/dev/null || sync; done ) &
      wait
    " </dev/null >/dev/null 2>&1
  ) &
done
wait
sleep 2

# harvest: scope each node's dmesg to after its marker; count the signals
D=$(mktemp -d)
for i in $(seq 1 "$N"); do
  (
    timeout 15 $SSH test$i "
      dmesg | awk '/MXFS_YSR_MARK $TAG/{f=1} f' > /tmp/ysr_win.txt
      echo exh=\$(grep -c 'P-CAWEXH.*yreg=' /tmp/ysr_win.txt) \
           shut=\$(grep -c 'Shutting down filesystem' /tmp/ysr_win.txt) \
           p221=\$(grep -c 'P221-YIELD-BOUND' /tmp/ysr_win.txt) \
           mnt=\$(mount -t mxfs 2>/dev/null | wc -l)
    " </dev/null 2>/dev/null | sed "s/^/test$i /" > "$D/$i"
  ) &
done
wait

cat "$D"/* | sort -t t -k2 -n
EXH=$(cat "$D"/* | grep -oE 'exh=[0-9]+'  | awk -F= '{s+=$2} END{print s+0}')
SHT=$(cat "$D"/* | grep -oE 'shut=[0-9]+' | awk -F= '{s+=$2} END{print s+0}')
P221=$(cat "$D"/* | grep -oE 'p221=[0-9]+'| awk -F= '{s+=$2} END{print s+0}')
LOSTMNT=$(cat "$D"/* | grep -cE 'mnt=0')
echo "== arm=$ARM dur=${DUR}s: exhaustions=$EXH shutdowns=$SHT p221_bypasses=$P221 lost_mounts=$LOSTMNT"
[ "$SHT" -gt 0 ] && exit 20
[ "$EXH" -gt 0 ] && exit 10
exit 0
