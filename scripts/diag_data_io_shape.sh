#!/bin/bash
# diag_data_io_shape.sh — compare block-I/O shape of a 700MB dd+fsync on
# native XFS vs single-node mxfs (sess21 ccloop: data path 3.6x slower).
# Prints /proc/diskstats deltas for the LUN: write ios, write sectors
# (avg req size), write ticks, flush ios (fields 16/17, kernel >=5.5).
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/../tests/criteria/lib.sh"
: "${MXFS_SSH_TIMEOUT:=600}"

NODE=${1:-test1}
DISK=$(basename "$MXFS_DEV")

SNIPPET='
snap() { awk -v d='"$DISK"' "\$3==d {print \$8, \$10, \$11, \$16, \$17}" /proc/diskstats; }
b=$(snap)
t0=$(date +%s%N)
dd if=/dev/zero of='"$MXFS_MOUNT"'/bigfile bs=1M count=700 conv=fsync >/dev/null 2>&1
t1=$(date +%s%N)
a=$(snap)
read bw bs bt bf bft <<< "$b"
read aw as at af aft <<< "$a"
wios=$((aw-bw)); wsec=$((as-bs)); wt=$((at-bt)); fios=$((af-bf)); ft=$((aft-bft))
echo "wall_ms=$(( (t1-t0)/1000000 )) write_ios=$wios write_sectors=$wsec avg_kb=$(( wios>0 ? wsec/2/wios : 0 )) write_ticks_ms=$wt flush_ios=$fios flush_ticks_ms=$ft"
'

teardown_all "$NODE"
echo "=== native XFS ==="
ssh_node "$NODE" "
    wipefs -aq $MXFS_DEV 2>/dev/null
    mkfs.xfs -f -q $MXFS_DEV >/dev/null 2>&1 || { echo MKFS_XFS_FAIL; exit 1; }
    mkdir -p $MXFS_MOUNT && mount -t xfs $MXFS_DEV $MXFS_MOUNT || { echo MOUNT_XFS_FAIL; exit 1; }
    $SNIPPET
    umount $MXFS_MOUNT"

echo "=== mxfs single-node ==="
teardown_all "$NODE"
fresh_cluster_mount "$NODE" || { echo "MXFS MOUNT FAIL"; exit 1; }
ssh_node "$NODE" "$SNIPPET"
ssh_node "$NODE" "umount $MXFS_MOUNT"
