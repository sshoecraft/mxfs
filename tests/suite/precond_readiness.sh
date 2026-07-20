#!/bin/bash
# precond_readiness — P0 gate: confirm the node has a healthy, writable MXFS
# mount before any real test runs. Agnostic: $1 = mount point only.

SUITE_TEST_NAME=precond_readiness
MNT="${1:-/mnt/shared}"
NODES="${MXFS_NODES:-1}"
# Normally mxfs; the native-XFS timing baseline (run.sh DLM=xfs, N=1 only)
# mounts plain xfs instead — this gate should still pass there, just checking
# for the FS type run.sh actually put on the mount.
FSTYPE="${MXFS_EXPECT_FSTYPE:-mxfs}"
source "$(dirname "$(readlink -f "$0")")/lib.sh"

ck   "is a mountpoint"   mountpoint -q "$MNT"
ck   "type is $FSTYPE"   grep -q " $MNT $FSTYPE " /proc/mounts

W="$MNT/.suite_readiness.$(hostname).$$"
ck   "mkdir on mount"    mkdir -p "$W"
echo hi > "$W/f" 2>/dev/null
ckeq "write/read back"   "hi" "$(cat "$W/f" 2>/dev/null)"
ck   "fsync ok"          dd if=/dev/zero of="$W/s" bs=4096 count=1 oflag=dsync status=none
ck   "unlink/cleanup"    rm -rf "$W"

avail=$(df -P "$MNT" 2>/dev/null | awk 'NR==2{print $4}')
ck   "has free space"    test "${avail:-0}" -gt 0

finish
