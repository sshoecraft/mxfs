#!/bin/bash
# Criterion: chk_mxfs validates a healthy FS with zero false positives.
# Verifier: mkfs a fresh FS, mount it on N nodes, do a small workload,
# unmount, run chk_mxfs.  Threshold: chk_mxfs exits 0 with zero errors
# reported.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "chk_clean"
set_script_timeout 60

parse_common_args "$@"
# Default to 2 nodes for speed
[ "${#NODES[@]}" -gt 2 ] && NODES=("${NODES[@]:0:2}")
NODE0="${NODES[0]}"
REST=("${NODES[@]:1}")

teardown_all "${NODES[*]}"
fresh_cluster_mount "$NODE0" "${REST[@]}" \
    || result_fail "n/a" "all-nodes-mounted" "cluster mount failed"

# Tiny smoke workload so the FS isn't completely empty
ssh_node_quiet "$NODE0" "mkdir -p $MXFS_MOUNT/chk_test; for i in \$(seq 1 32); do echo data > $MXFS_MOUNT/chk_test/f\$i; done; sync"

# Unmount everywhere (chk_mxfs must run on an idle device)
parallel_ssh_quiet "${NODES[*]}" "umount $MXFS_MOUNT 2>/dev/null"

# Run chk_mxfs on node 0
out=$(ssh_node "$NODE0" "$MXFS_CHK $MXFS_DEV 2>&1; echo CHK_RC=\$?")
rc=$(echo "$out" | grep '^CHK_RC=' | tail -1 | cut -d= -f2)
# Count any line containing ERROR / error / corrupt
errors=$(echo "$out" | grep -cEi 'error|corrupt|bad |invalid' | tr -d ' \r\n')

ssh_node_quiet "$NODE0" "rmmod mxfs 2>/dev/null"

[ "$rc" = "0" ] || result_fail "rc=$rc errors=$errors" "rc=0 errors=0" "chk_mxfs nonzero exit"
[ "$errors" = "0" ] || result_fail "rc=$rc errors=$errors" "rc=0 errors=0" "chk_mxfs reported errors"
result_pass "rc=0 errors=0" "rc=0 errors=0"
