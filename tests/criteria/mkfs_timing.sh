#!/bin/bash
# Criterion: mkfs.mxfs completes in seconds for typical LUNs.
# Verifier: format the test LUN, measure wall.  Threshold: <= 10s on the
# 50 GiB test LUN.  Native mkfs.xfs on the same LUN is ~1s; mxfs writes
# the superblock + journal region + disklock region + delegates to XFS,
# so a few seconds is acceptable; tens of seconds is not.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "mkfs_timing"
set_script_timeout 60

parse_common_args "$@"
NODE="${NODES[0]}"
THRESHOLD_MS=10000

# Tear down anything that might hold the device, then time mkfs.
ssh_node_quiet "$NODE" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null; true"
out=$(ssh_node "$NODE" "
    $MXFS_PREP >/tmp/prep.log 2>&1 || { echo PREP_FAIL; exit 1; }
    t0=\$(date +%s%N)
    echo y | $MXFS_MKFS $MXFS_DEV >/tmp/mkfs.log 2>&1
    rc=\$?
    t1=\$(date +%s%N)
    echo MKFS_RC=\$rc
    echo MKFS_MS=\$(( (t1 - t0) / 1000000 ))
")
rc=$(echo "$out" | grep '^MKFS_RC=' | tail -1 | cut -d= -f2)
ms=$(echo "$out" | grep '^MKFS_MS=' | tail -1 | cut -d= -f2)
ms=${ms:-0}

[ "$rc" = "0" ] || result_fail "${ms}ms" "<=${THRESHOLD_MS}ms" "mkfs returned rc=$rc"
[ "$ms" -le "$THRESHOLD_MS" ] || result_fail "${ms}ms" "<=${THRESHOLD_MS}ms" "mkfs too slow"
result_pass "${ms}ms" "<=${THRESHOLD_MS}ms"
