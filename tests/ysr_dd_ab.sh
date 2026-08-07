#!/bin/bash
# ysr_dd_ab.sh — one dirent_durability lap for a given D-CAW-YIELD-STARVATION
# arm, with scoped exhaustion/shutdown harvest.  Alternate arms across laps on
# an AGING mount (no re-prep between laps unless nodes died) — aging raises
# contention, which is the regime the defect needs.
#
# Usage: tests/ysr_dd_ab.sh <nnodes> <fix|control>
# Prints one summary line:  LAP arm=<arm> verdict=<PASS|FAIL> exh=N shut=N p221=N
# Exit 0 always (the caller reads the line); exit 2 on setup failure.
#
# RULE 0 budget: dirent_durability 240s manifest budget + ~60s overhead.

set -u
cd "$(dirname "$0")/.."
N=${1:?nnodes}
ARM=${2:?fix|control}
SSH=tools/mxfs_sshpass.sh
case "$ARM" in
  fix) REG=1;; control) REG=0;; *) echo "bad arm"; exit 2;;
esac
TAG="ysrdd_$(date +%s)"

for i in $(seq 1 "$N"); do
  ( timeout 12 $SSH test$i "echo $REG > /sys/module/mxfs/parameters/caw_fresh_register; echo \"MXFS_YSR_MARK $TAG\" > /dev/kmsg" </dev/null >/dev/null 2>&1 ) &
done
wait

OUT=$(timeout 400 ./run.sh "$N" caw dirent_durability 2>&1 | grep -E "PASS|FAIL|BLOCK" | tail -1)
V=$(echo "$OUT" | grep -oE "PASS|FAIL|BLOCK" | head -1)

D=$(mktemp -d)
for i in $(seq 1 "$N"); do
  (
    timeout 15 $SSH test$i "
      dmesg | awk '/MXFS_YSR_MARK $TAG/{f=1} f' > /tmp/ysr_win.txt
      echo exh=\$(grep -c 'P-CAWEXH.*yreg=' /tmp/ysr_win.txt) \
           shut=\$(grep -c 'Shutting down filesystem' /tmp/ysr_win.txt) \
           p221=\$(grep -c 'P221-YIELD-BOUND' /tmp/ysr_win.txt)
    " </dev/null 2>/dev/null > "$D/$i"
  ) &
done
wait
EXH=$(cat "$D"/* 2>/dev/null | grep -oE 'exh=[0-9]+'  | awk -F= '{s+=$2} END{print s+0}')
SHT=$(cat "$D"/* 2>/dev/null | grep -oE 'shut=[0-9]+' | awk -F= '{s+=$2} END{print s+0}')
P221=$(cat "$D"/* 2>/dev/null | grep -oE 'p221=[0-9]+'| awk -F= '{s+=$2} END{print s+0}')
echo "LAP arm=$ARM verdict=${V:-UNKNOWN} exh=$EXH shut=$SHT p221=$P221 detail: $OUT"
