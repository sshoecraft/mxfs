#!/bin/bash
# Cluster test: all nodes concurrently write to separate files, verify integrity
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "concurrent_write"

TESTDIR="$MOUNT_POINT/.mxfs_test/concurrent_write"
mkdir -p "$TESTDIR" 2>/dev/null

FILE_SIZE=262144  # 256KB per file
FILES_PER_NODE=10

# Barrier: synchronize start
barrier_signal "cw_ready"
barrier_wait "cw_ready" "$TOTAL_NODES"

# Each node writes multiple files with verifiable content
log_info "Node ${NODE_ID}: writing ${FILES_PER_NODE} files of ${FILE_SIZE} bytes..."
ts_write=$(time_op)
for i in $(seq 1 $FILES_PER_NODE); do
    dd if=/dev/urandom of="/tmp/mxfs_cw_${NODE_ID}_${i}" bs=$FILE_SIZE count=1 2>/dev/null
    cp "/tmp/mxfs_cw_${NODE_ID}_${i}" "$TESTDIR/node${NODE_ID}_data${i}"
    md5sum "/tmp/mxfs_cw_${NODE_ID}_${i}" | awk '{print $1}' > "$TESTDIR/node${NODE_ID}_data${i}.md5"
    rm -f "/tmp/mxfs_cw_${NODE_ID}_${i}"
done
sync
log_timing "write_${FILES_PER_NODE}x256KB" "$(time_elapsed_ms "$ts_write")"

# Barrier: all writes done
barrier_signal "cw_write_done"
barrier_wait "cw_write_done" "$TOTAL_NODES"
sleep 2

# Each node verifies its own files
for i in $(seq 1 $FILES_PER_NODE); do
    expected_md5=$(cat "$TESTDIR/node${NODE_ID}_data${i}.md5")
    actual_md5=$(md5sum "$TESTDIR/node${NODE_ID}_data${i}" | awk '{print $1}')
    assert_equals "$expected_md5" "$actual_md5" "Own file node${NODE_ID}_data${i} integrity"
done

# Each node cross-verifies the next node's files
read_node=$(( (NODE_ID % TOTAL_NODES) + 1 ))
log_info "Node ${NODE_ID}: cross-verifying node ${read_node} files..."
ts_xverify=$(time_op)
for i in $(seq 1 $FILES_PER_NODE); do
    expected_md5=$(cat "$TESTDIR/node${read_node}_data${i}.md5")
    actual_md5=$(md5sum "$TESTDIR/node${read_node}_data${i}" | awk '{print $1}')
    assert_equals "$expected_md5" "$actual_md5" "Cross-verify node${read_node}_data${i}"
done
log_timing "cross_verify_${FILES_PER_NODE}_files" "$(time_elapsed_ms "$ts_xverify")"

# Barrier: verification done
barrier_signal "cw_verify"
barrier_wait "cw_verify" "$TOTAL_NODES"

test_end
