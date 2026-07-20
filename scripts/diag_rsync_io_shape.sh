#!/bin/bash
# diag_rsync_io_shape.sh — trace block_rq_issue during the canonical
# rsync on native XFS vs single-node mxfs and print request histograms
# (sess21 ccloop: rsync 1.67x after data-path large-folio fix; bisect
# the remaining overhead).
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/../tests/criteria/lib.sh"
: "${MXFS_SSH_TIMEOUT:=600}"

NODE=${1:-test1}

SNIPPET='
T=/sys/kernel/debug/tracing
echo 0 > $T/tracing_on; echo > $T/trace; echo 1 > $T/events/block/block_rq_issue/enable; echo 1 > $T/tracing_on
t0=$(date +%s%N)
mkdir -p '"$MXFS_MOUNT"'/dest
rsync -a --no-i-r /root/open-gpu-kernel-modules/ '"$MXFS_MOUNT"'/dest/ >/dev/null 2>&1
sync
t1=$(date +%s%N)
echo 0 > $T/tracing_on; echo 0 > $T/events/block/block_rq_issue/enable
echo "wall_ms=$(( (t1-t0)/1000000 ))"
echo "--- op histogram (op count avg_sectors) ---"
awk "/8,0/ {for(i=1;i<=NF;i++) if(\$(i+1)==\"+\") {print \$(i-3), \$(i+2); break}}" $T/trace | awk "{c[\$1]++; t[\$1]+=\$2} END {for(o in c) print o, c[o], int(t[o]/c[o])}" | sort -k2 -rn
echo "--- total ---"
awk "/8,0/ {n++} END {print \"total_ios=\"n}" $T/trace
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
