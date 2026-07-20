#!/bin/bash
# Decisive on-disk-vs-cache test for the concurrent-rename lost-update.
# 1. All nodes concurrently create+rename 20 files each in a shared dir.
# 2. Count *_after_* entries each node SEES (cached view).
# 3. Unmount+remount test1, then count *_after_* entries on disk.
#    expected = nodes*20.  If the remounted count < expected => entries are
#    LOST ON DISK (real lost-update).  If == expected => reader cache
#    staleness only (eventually-consistent).
set -u
cd "$(dirname "$0")/.."
NODES=(test1 test2 test3 test4); N=20
PASS=/tmp/.mxfs_pass; MNT=/mnt/shared; DIR="$MNT/.mxfs_test/odc"; SSH=tools/mxfs_sshpass.sh
exp=$(( ${#NODES[@]} * N ))

timeout 30 $SSH test1 $PASS "rm -rf $DIR; mkdir -p $DIR; sync" >/dev/null 2>&1
# phase 1 create (parallel)
pids=(); for idx in "${!NODES[@]}"; do id=$((idx+1)); n="${NODES[$idx]}"
  ( timeout 60 $SSH "$n" $PASS "for i in \$(seq 1 $N); do echo c_${id}_\$i > $DIR/n${id}_b_\$i; done; sync" >/dev/null 2>&1 ) & pids+=($!); done
for p in "${pids[@]}"; do wait "$p"; done
# phase 2 rename (parallel)
pids=(); for idx in "${!NODES[@]}"; do id=$((idx+1)); n="${NODES[$idx]}"
  ( timeout 60 $SSH "$n" $PASS "for i in \$(seq 1 $N); do mv $DIR/n${id}_b_\$i $DIR/n${id}_a_\$i; done; sync" >/dev/null 2>&1 ) & pids+=($!); done
for p in "${pids[@]}"; do wait "$p"; done
sleep 2

echo "expected after-entries: $exp"
echo "=== cached view per node ==="
for n in "${NODES[@]}"; do printf "%s sees: " "$n"; timeout 20 $SSH "$n" $PASS "ls $DIR | grep -c _a_" 2>/dev/null; done

echo "=== remount test1, count on-disk ==="
timeout 60 $SSH test1 $PASS "umount $MNT 2>/dev/null; sleep 1; mount -t mxfs /dev/sda $MNT 2>&1 | tail -1; sleep 1; echo -n 'on-disk after-entries: '; ls $DIR | grep -c _a_" 2>/dev/null
