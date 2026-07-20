#!/bin/bash
# Cluster test: all nodes concurrently create directories
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "concurrent_mkdir"

TESTDIR="$MOUNT_POINT/.mxfs_test/concurrent_mkdir"
mkdir -p "$TESTDIR" 2>/dev/null

DIRS_PER_NODE=50

# Barrier: synchronize start
barrier_signal "cm_ready"
barrier_wait "cm_ready" "$TOTAL_NODES"

# All nodes create directories simultaneously
log_info "Node ${NODE_ID}: creating ${DIRS_PER_NODE} directories..."
ts_mkdir=$(time_op)
for i in $(seq 1 $DIRS_PER_NODE); do
    mkdir "$TESTDIR/node${NODE_ID}_dir${i}" || {
        test_fail "Failed to create node${NODE_ID}_dir${i}"
    }
    # Put a file in each dir as marker
    touch "$TESTDIR/node${NODE_ID}_dir${i}/marker"
done
log_timing "mkdir_${DIRS_PER_NODE}_dirs" "$(time_elapsed_ms "$ts_mkdir")"

# Barrier: all creates done
barrier_signal "cm_create_done"
barrier_wait "cm_create_done" "$TOTAL_NODES"
sleep 2

# Verify own directories
for i in $(seq 1 $DIRS_PER_NODE); do
    assert_dir_exists "$TESTDIR/node${NODE_ID}_dir${i}" "Own dir node${NODE_ID}_dir${i} exists"
    assert_file_exists "$TESTDIR/node${NODE_ID}_dir${i}/marker" "Marker in node${NODE_ID}_dir${i}"
done

# Node 1 verifies global count
if [ "$NODE_ID" = "1" ]; then
    expected=$((TOTAL_NODES * DIRS_PER_NODE))
    # sess34 H17: count via find both BEFORE and AFTER drop_caches.
    # If pre/post counts differ, test1's cache was missing entries that
    # exist on disk → cache-invalidation bug.  If pre==post, the entries
    # are missing from disk too → write-side bug.
    actual_pre=$(find "$TESTDIR" -maxdepth 1 -type d -name 'node*_dir*' | wc -l | tr -d ' ')
    log_info "P-H17: count BEFORE drop_caches=${actual_pre}"
    sudo sync; sudo bash -c 'echo 3 > /proc/sys/vm/drop_caches' 2>/dev/null || true
    actual_post=$(find "$TESTDIR" -maxdepth 1 -type d -name 'node*_dir*' | wc -l | tr -d ' ')
    log_info "P-H17: count AFTER drop_caches=${actual_post}"
    actual="$actual_post"
    assert_equals "$expected" "$actual" "Total directory count: ${expected}"
fi

# Barrier: verification complete
barrier_signal "cm_verify"
barrier_wait "cm_verify" "$TOTAL_NODES"

test_end
