#!/bin/bash
# Cluster test: all nodes concurrently touch files in same directory
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "concurrent_touch"

TESTDIR="$MOUNT_POINT/.mxfs_test/concurrent_touch"
mkdir -p "$TESTDIR" 2>/dev/null

FILES_PER_NODE=100

# Barrier: synchronize start for maximum concurrency
barrier_signal "ct_ready"
barrier_wait "ct_ready" "$TOTAL_NODES"

# All nodes create files simultaneously
log_info "Node ${NODE_ID}: creating ${FILES_PER_NODE} files..."
ts_touch=$(time_op)
for i in $(seq 1 $FILES_PER_NODE); do
    touch "$TESTDIR/node${NODE_ID}_file${i}" || {
        test_fail "Failed to create node${NODE_ID}_file${i}"
    }
done
log_timing "touch_${FILES_PER_NODE}_files" "$(time_elapsed_ms "$ts_touch")"

# Barrier: all creates done
barrier_signal "ct_create_done"
barrier_wait "ct_create_done" "$TOTAL_NODES"
sleep 2

# Each node verifies its own files exist
for i in $(seq 1 $FILES_PER_NODE); do
    assert_file_exists "$TESTDIR/node${NODE_ID}_file${i}" "Own file node${NODE_ID}_file${i} exists"
done

# Node 1 does the global count verification
if [ "$NODE_ID" = "1" ]; then
    expected=$((TOTAL_NODES * FILES_PER_NODE))
    actual=$(ls "$TESTDIR"/node*_file* 2>/dev/null | wc -l)
    actual=$(echo "$actual" | tr -d ' ')
    assert_equals "$expected" "$actual" "Total file count: ${expected}"

    # Verify no duplicate names (each file unique)
    unique=$(ls "$TESTDIR"/node*_file* 2>/dev/null | sort -u | wc -l)
    unique=$(echo "$unique" | tr -d ' ')
    assert_equals "$expected" "$unique" "All file names unique"
fi

# Barrier: verification complete
barrier_signal "ct_verify"
barrier_wait "ct_verify" "$TOTAL_NODES"

test_end
