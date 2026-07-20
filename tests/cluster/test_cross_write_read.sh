#!/bin/bash
# Cluster test: node A writes data, node B reads and verifies integrity
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "cross_write_read"

TESTDIR="$MOUNT_POINT/.mxfs_test/cross_write_read"
mkdir -p "$TESTDIR" 2>/dev/null

# Phase 1: Each node writes a 1MB file with known content
log_info "Node ${NODE_ID}: writing 1MB test file..."
ts_write=$(time_op)
dd if=/dev/urandom of="/tmp/mxfs_cwr_${NODE_ID}" bs=1M count=1 2>/dev/null
cp "/tmp/mxfs_cwr_${NODE_ID}" "$TESTDIR/data_node${NODE_ID}"
sync
log_timing "write_1MB" "$(time_elapsed_ms "$ts_write")"

# Write checksum to a sidecar file
md5sum "/tmp/mxfs_cwr_${NODE_ID}" | awk '{print $1}' > "$TESTDIR/data_node${NODE_ID}.md5"
rm -f "/tmp/mxfs_cwr_${NODE_ID}"

# Barrier: all writes complete
barrier_signal "cwr_write"
barrier_wait "cwr_write" "$TOTAL_NODES"
sleep 2

# Phase 2: Each node reads the NEXT node's file (round-robin)
read_node=$(( (NODE_ID % TOTAL_NODES) + 1 ))
log_info "Node ${NODE_ID}: reading data from node ${read_node}..."

ts_read=$(time_op)
expected_md5=$(cat "$TESTDIR/data_node${read_node}.md5")
actual_md5=$(md5sum "$TESTDIR/data_node${read_node}" | awk '{print $1}')
assert_equals "$expected_md5" "$actual_md5" "Node ${NODE_ID} reads node ${read_node} data with correct md5"

# Verify size
sz=$(stat -c%s "$TESTDIR/data_node${read_node}")
assert_equals "1048576" "$sz" "Node ${read_node} file is 1MB"
log_timing "read_1MB" "$(time_elapsed_ms "$ts_read")"

# Phase 3: Each node reads ALL other nodes' files
log_info "Node ${NODE_ID}: verifying all ${TOTAL_NODES} files..."
ts_verifyall=$(time_op)
for n in $(seq 1 "$TOTAL_NODES"); do
    expected_md5=$(cat "$TESTDIR/data_node${n}.md5")
    actual_md5=$(md5sum "$TESTDIR/data_node${n}" | awk '{print $1}')
    assert_equals "$expected_md5" "$actual_md5" "Node ${NODE_ID} verifies node ${n} integrity"
done
log_timing "verify_all" "$(time_elapsed_ms "$ts_verifyall")"

# Barrier: all verification complete
barrier_signal "cwr_verify"
barrier_wait "cwr_verify" "$TOTAL_NODES"

test_end
