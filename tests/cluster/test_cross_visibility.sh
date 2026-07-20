#!/bin/bash
# Cluster test: file created on one node is visible on all others
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "cross_visibility"

TESTDIR="$MOUNT_POINT/.mxfs_test/cross_visibility"
mkdir -p "$TESTDIR" 2>/dev/null

# Phase 1: Each node creates a unique file
ts_create=$(time_op)
echo "hello from node ${NODE_ID}" > "$TESTDIR/node${NODE_ID}.txt"
sync
log_timing "create_file" "$(time_elapsed_ms "$ts_create")"

# Barrier: wait for all nodes to finish writing
barrier_signal "cv_write_done"
barrier_wait "cv_write_done" "$TOTAL_NODES"

# Small settle time for cache invalidation
sleep 2

# Phase 2: Each node verifies it can see ALL other nodes' files
ts_verify=$(time_op)
missing=0
for n in $(seq 1 "$TOTAL_NODES"); do
    if [ ! -f "$TESTDIR/node${n}.txt" ]; then
        test_fail "Node ${NODE_ID} cannot see node${n}.txt"
        missing=$((missing + 1))
    else
        content=$(cat "$TESTDIR/node${n}.txt")
        assert_equals "hello from node ${n}" "$content" "Node ${NODE_ID} reads correct content from node ${n}"
    fi
done
log_timing "cross_verify" "$(time_elapsed_ms "$ts_verify")"

if [ "$missing" -eq 0 ]; then
    assert_true "Node ${NODE_ID} sees all ${TOTAL_NODES} files"
fi

# Barrier: all done verifying
barrier_signal "cv_verify_done"
barrier_wait "cv_verify_done" "$TOTAL_NODES"

test_end
