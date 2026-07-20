#!/bin/bash
# Criterion: Strong consistency for fsync'd writes across nodes — a
# reader on node B sees writes as soon as writer on node A's fsync
# returns.  Verifier: wrap the existing tests/cluster/test_sequential_
# consistency.sh and tests/cluster/test_cross_write_read.sh; assert pass.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "strong_consistency"
set_script_timeout 900

parse_common_args "$@"
N=${#NODES[@]}
[ "$N" -ge 2 ] || result_fail "n/a" "need-2-nodes" "needs >= 2 nodes"

# Map logical node 1..N to test17..test32 (the mxfs.1 cluster)
export MXFS_NODE_OFFSET=16
# Point the harness at this repo's tests — the cluster has /src
# NFS-mounted from the dev host, not /mnt/mxfs-src.
: "${MXFS_TESTS_DIR:=${MXFS_REPO}/tests}"
export MXFS_TESTS_DIR

# Bring up a fresh cluster mount — run_tests.sh requires it pre-mounted
NODE0="${NODES[0]}"
REST=("${NODES[@]:1}")
teardown_all "${NODES[*]}"
fresh_cluster_mount "$NODE0" "${REST[@]}" \
    || result_fail "n/a" "mount-ok" "cluster mount failed before harness invoke"

TESTS=(test_sequential_consistency test_cross_write_read test_large_file_integrity)
LOG=$(mktemp -t strong_consistency.XXXXXX.log)
failed=0; passed=0
for t in "${TESTS[@]}"; do
    MXFS_NODE_OFFSET=16 "$MXFS_REPO/tests/run_tests.sh" --nodes "$N" --phase cluster --test "$t" \
        --pass-file "$MXFS_PASS" --device "$MXFS_DEV" --mount-point "$MXFS_MOUNT" \
        >> "$LOG" 2>&1
    rc=$?
    if [ "$rc" = "0" ]; then passed=$((passed+1)); else failed=$((failed+1)); fi
done

parallel_ssh_quiet "${NODES[*]}" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"

measured="passed=$passed failed=$failed"
threshold="failed=0"
[ "$failed" = "0" ] || result_fail "$measured" "$threshold" "see $LOG"
result_pass "$measured" "$threshold"
