#!/bin/bash
# Criterion: No false ENOENT/EEXIST under concurrent access; cache
# coherency is correct.  Verifier: run the existing cluster tests that
# already check this — test_cross_visibility, test_rename_visibility,
# test_unlink_visibility — and assert all pass.  Threshold: 0 failures.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "cache_coherency"
set_script_timeout 900

parse_common_args "$@"
N=${#NODES[@]}
[ "$N" -ge 2 ] || result_fail "n/a" "need-2-nodes" "cache coherency requires >= 2 nodes"

# The wrapped harness numbers nodes from 1; our cluster lives on
# test17..test32, so offset accordingly.
export MXFS_NODE_OFFSET=16
# run_tests.sh expects the test scripts under MXFS_TESTS_DIR.  The
# mxfs.1 cluster has /src NFS-mounted from the dev host, so point at
# this repo's tests directory rather than the default /mnt/mxfs-src.
: "${MXFS_TESTS_DIR:=${MXFS_REPO}/tests}"
export MXFS_TESTS_DIR

# run_tests.sh expects mxfs already mounted on every node — it does
# NOT mount.  Bring up a fresh cluster mount first.
NODE0="${NODES[0]}"
REST=("${NODES[@]:1}")
teardown_all "${NODES[*]}"
fresh_cluster_mount "$NODE0" "${REST[@]}" \
    || result_fail "n/a" "mount-ok" "cluster mount failed before harness invoke"

TESTS=(test_cross_visibility test_rename_visibility test_unlink_visibility test_cross_write_read)
LOG=$(mktemp -t cache_coherency.XXXXXX.log)
failed=0; passed=0
for t in "${TESTS[@]}"; do
    MXFS_NODE_OFFSET=16 "$MXFS_REPO/tests/run_tests.sh" --nodes "$N" --phase cluster --test "$t" \
        --pass-file "$MXFS_PASS" --device "$MXFS_DEV" --mount-point "$MXFS_MOUNT" \
        >> "$LOG" 2>&1
    rc=$?
    if [ "$rc" = "0" ]; then passed=$((passed+1)); else failed=$((failed+1)); fi
done

# Tear down so the next criterion gets a clean slate
parallel_ssh_quiet "${NODES[*]}" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"

measured="passed=$passed failed=$failed of=${#TESTS[@]}"
threshold="failed=0"
[ "$failed" = "0" ] || result_fail "$measured" "$threshold" "see $LOG"
result_pass "$measured" "$threshold"
