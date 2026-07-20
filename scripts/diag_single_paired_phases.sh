#!/bin/bash
# diag_single_paired_phases.sh — bisect the single_node_paired overhead
# (sess21 ccloop: mxfs ~5s vs xfs ~3s on the canonical rsync).  Runs the
# same phase workloads on native XFS and single-node mxfs on the same
# LUN and prints per-phase walls:
#   data:  dd 700MB sequential write + sync
#   meta:  create 8000 empty files across 80 dirs + sync
#   rsync: the canonical tree (reference)
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/../tests/criteria/lib.sh"
: "${MXFS_SSH_TIMEOUT:=600}"

NODE=${1:-test1}

PHASES='
run_phase() {
    local label="$1" cmd="$2" t0 t1
    cd '"$MXFS_MOUNT"' || { echo "${label}_ms=FAIL_cd"; return; }
    t0=$(date +%s%N)
    eval "$cmd" >/dev/null 2>&1
    sync
    t1=$(date +%s%N)
    echo "${label}_ms=$(( (t1 - t0) / 1000000 ))"
    cd /
}
run_phase data "dd if=/dev/zero of=./bigfile bs=1M count=700 conv=fsync"
run_phase meta "mkdir -p d{0..79} && for d in d*; do for i in \$(seq 1 100); do : > \$d/f\$i; done; done"
run_phase rsync "mkdir -p ./dest && rsync -a --no-i-r /root/open-gpu-kernel-modules/ ./dest/"
'

teardown_all "$NODE"

echo "=== native XFS ==="
ssh_node "$NODE" "
    wipefs -aq $MXFS_DEV 2>/dev/null
    mkfs.xfs -f -q $MXFS_DEV >/dev/null 2>&1 || { echo MKFS_XFS_FAIL; exit 1; }
    mkdir -p $MXFS_MOUNT && mount -t xfs $MXFS_DEV $MXFS_MOUNT || { echo MOUNT_XFS_FAIL; exit 1; }
    $PHASES
    cd /; umount $MXFS_MOUNT"

echo "=== mxfs single-node ==="
teardown_all "$NODE"
fresh_cluster_mount "$NODE" || { echo "MXFS MOUNT FAIL"; exit 1; }
ssh_node "$NODE" "$PHASES"
ssh_node "$NODE" "cd /; umount $MXFS_MOUNT"
