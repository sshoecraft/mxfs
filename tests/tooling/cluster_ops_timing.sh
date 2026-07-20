#!/bin/bash
# cluster_ops_timing — mount/unmount complete in seconds (lifecycle). Device-aware.
SUITE_TEST_NAME=cluster_ops_timing
MNT="${1:-/mnt/shared}"; NODES="${MXFS_NODES:-1}"
DEV="${MXFS_DEV:-/dev/sda}"; MODULE="${MXFS_MODULE:-/src/mxfs/mxfs.ko}"; MKFS="${MKFS_MXFS:-/src/mxfs/tools/mkfs_mxfs}"
FIRST_MAX="${FIRST_MAX_MS:-15000}"; REST_MAX="${REST_MAX_MS:-10000}"; UM_MAX="${UM_MAX_MS:-10000}"
# native-XFS baseline (run.sh DLM=xfs, N=1 only): plain xfs mount/umount, no
# module load / DLM formation (xfs isn't clustered) -- "first" has no formation
# overhead to amortize here, but the raw mount/umount floor is still useful.
FSTYPE="${MXFS_EXPECT_FSTYPE:-mxfs}"
emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }
ms(){ date +%s%3N; }
mountpoint -q "$MNT" && umount "$MNT"
mkdir -p "$MNT"
if [ "$FSTYPE" = xfs ]; then
    mkfs.xfs -f "$DEV" >/dev/null 2>&1 || { emit FAIL setup mkfs; exit 1; }
    t=$(ms); mount "$DEV" "$MNT" || { emit FAIL mount "first mount failed"; exit 1; }; first=$(( $(ms) - t ))
    t=$(ms); umount "$MNT"      || { emit FAIL umount "umount failed"; exit 1; };       um=$(( $(ms) - t ))
    t=$(ms); mount "$DEV" "$MNT" || { emit FAIL mount "remount failed"; exit 1; };      rest=$(( $(ms) - t ))
else
modprobe libcrc32c 2>/dev/null || true
lsmod | grep -q '^mxfs' || insmod "$MODULE" force_transport=1 || { emit FAIL setup insmod; exit 1; }
"$MKFS" -f "$DEV" >/dev/null 2>&1 || { emit FAIL setup mkfs; exit 1; }
t=$(ms); mount -t mxfs "$DEV" "$MNT" || { emit FAIL mount "first mount failed"; exit 1; }; first=$(( $(ms) - t ))
t=$(ms); umount "$MNT"            || { emit FAIL umount "umount failed"; exit 1; };       um=$(( $(ms) - t ))
t=$(ms); mount -t mxfs "$DEV" "$MNT" || { emit FAIL mount "remount failed"; exit 1; };    rest=$(( $(ms) - t ))
fi
measured="first=${first}ms rest=${rest}ms umount=${um}ms"
if [ "$first" -le "$FIRST_MAX" ] && [ "$rest" -le "$REST_MAX" ] && [ "$um" -le "$UM_MAX" ]; then
  emit PASS "$measured"
else
  emit FAIL "$measured" "exceeds first<=${FIRST_MAX}/rest<=${REST_MAX}/um<=${UM_MAX}ms"
fi
