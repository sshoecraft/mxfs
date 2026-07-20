#!/bin/bash
# Stress test: create a single directory with thousands of entries across all nodes
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "large_dir"

TESTDIR="$MOUNT_POINT/.mxfs_test/large_dir"
mkdir -p "$TESTDIR/bigdir" 2>/dev/null

FILES_PER_NODE=500

# Barrier: synchronize start
barrier_signal "ld_ready"
barrier_wait "ld_ready" "$TOTAL_NODES"

# All nodes create files in the SAME directory
log_info "Node ${NODE_ID}: creating ${FILES_PER_NODE} files in shared directory..."
start_time=$(date +%s)

for i in $(seq 1 $FILES_PER_NODE); do
    echo "n${NODE_ID}" > "$TESTDIR/bigdir/n${NODE_ID}_f$(printf '%04d' $i)" || {
        test_fail "Failed to create file ${i}"
        break
    }
done
sync

end_time=$(date +%s)
elapsed=$((end_time - start_time))
log_info "Node ${NODE_ID}: created ${FILES_PER_NODE} files in ${elapsed}s"

# Barrier: creation done
barrier_signal "ld_create"
barrier_wait "ld_create" "$TOTAL_NODES"
sleep 3

# Verify own files
own_count=0
for i in $(seq 1 $FILES_PER_NODE); do
    fname="$TESTDIR/bigdir/n${NODE_ID}_f$(printf '%04d' $i)"
    if [ -f "$fname" ]; then
        own_count=$((own_count + 1))
    fi
done
assert_equals "$FILES_PER_NODE" "$own_count" "Node ${NODE_ID}: all ${FILES_PER_NODE} own files present"

# Node 1: verify total count via readdir
if [ "$NODE_ID" = "1" ]; then
    total_expected=$((TOTAL_NODES * FILES_PER_NODE))
    total_actual=$(ls "$TESTDIR/bigdir" 2>/dev/null | wc -l)
    total_actual=$(echo "$total_actual" | tr -d ' ')
    assert_equals "$total_expected" "$total_actual" "Total files in large dir: ${total_expected}"

    # Time the readdir
    rd_start=$(date +%s%N)
    ls "$TESTDIR/bigdir" > /dev/null 2>&1
    rd_end=$(date +%s%N)
    rd_ms=$(( (rd_end - rd_start) / 1000000 ))
    log_info "readdir of ${total_expected} entries: ${rd_ms}ms"
fi

# Barrier: verify done
barrier_signal "ld_verify"
barrier_wait "ld_verify" "$TOTAL_NODES"

test_end
