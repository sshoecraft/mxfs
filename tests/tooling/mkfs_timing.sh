#!/bin/bash
# mkfs_timing — mkfs_mxfs completes in seconds. Device-level (reads MXFS_DEV).
SUITE_TEST_NAME=mkfs_timing
MNT="${1:-/mnt/shared}"; NODES="${MXFS_NODES:-1}"
DEV="${MXFS_DEV:-/dev/sda}"; MKFS="${MKFS_MXFS:-/src/mxfs/tools/mkfs_mxfs}"
THRESH_MS="${MKFS_THRESHOLD_MS:-10000}"
# native-XFS timing baseline (run.sh DLM=xfs, N=1 only): time mkfs.xfs instead.
FSTYPE="${MXFS_EXPECT_FSTYPE:-mxfs}"
emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }
mountpoint -q "$MNT" && umount "$MNT" 2>/dev/null
if [ "$FSTYPE" = xfs ]; then
    t0=$(date +%s%3N); mkfs.xfs -f "$DEV" >/tmp/mkfs_timing.$$ 2>&1; rc=$?; t1=$(date +%s%3N)
else
[ -x "$MKFS" ] || { emit FAIL setup "mkfs tool missing $MKFS"; exit 1; }
t0=$(date +%s%3N); "$MKFS" -f "$DEV" >/tmp/mkfs_timing.$$ 2>&1; rc=$?; t1=$(date +%s%3N)
fi
ms=$((t1-t0)); rm -f /tmp/mkfs_timing.$$
[ $rc -eq 0 ] || { emit FAIL "rc=$rc ms=${ms}" "mkfs_mxfs failed"; exit 1; }
[ $ms -le $THRESH_MS ] && emit PASS "${ms}ms (threshold<=${THRESH_MS}ms)" || emit FAIL "${ms}ms" "exceeds ${THRESH_MS}ms"
