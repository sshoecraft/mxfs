#!/bin/bash
# Cluster test: unlink on one node, verify removal visible on all others
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "unlink_visibility"

TESTDIR="$MOUNT_POINT/.mxfs_test/unlink_visibility"
mkdir -p "$TESTDIR" 2>/dev/null

FILES_PER_NODE=30

# Phase 1: Each node creates files
log_info "Node ${NODE_ID}: creating ${FILES_PER_NODE} files..."
for i in $(seq 1 $FILES_PER_NODE); do
    echo "delete_me_${NODE_ID}_${i}" > "$TESTDIR/node${NODE_ID}_file${i}"
done

# Barrier: files created
barrier_signal "uv_create"
barrier_wait "uv_create" "$TOTAL_NODES"
sleep 1

# Verify all files exist before delete
total_expected=$((TOTAL_NODES * FILES_PER_NODE))
if [ "$NODE_ID" = "1" ]; then
    actual=$(ls "$TESTDIR"/node*_file* 2>/dev/null | wc -l)
    actual=$(echo "$actual" | tr -d ' ')
    assert_equals "$total_expected" "$actual" "All ${total_expected} files exist before deletion"
fi

# Barrier: pre-delete verification
barrier_signal "uv_preverify"
barrier_wait "uv_preverify" "$TOTAL_NODES"

# Phase 2: Each node deletes its files
log_info "Node ${NODE_ID}: deleting ${FILES_PER_NODE} files..."
ts_unlink=$(time_op)
for i in $(seq 1 $FILES_PER_NODE); do
    rm "$TESTDIR/node${NODE_ID}_file${i}" || {
        test_fail "Failed to delete node${NODE_ID}_file${i}"
    }
done
sync
log_timing "unlink_${FILES_PER_NODE}_files" "$(time_elapsed_ms "$ts_unlink")"

# Barrier: deletes done
barrier_signal "uv_delete"
barrier_wait "uv_delete" "$TOTAL_NODES"
sleep 2

# Phase 3: Each node verifies all files are gone
log_info "Node ${NODE_ID}: verifying all files deleted..."
ts_uvverify=$(time_op)
for n in $(seq 1 "$TOTAL_NODES"); do
    for i in $(seq 1 $FILES_PER_NODE); do
        assert_file_not_exists "$TESTDIR/node${n}_file${i}" "node${n}_file${i} deleted and gone"
    done
done
log_timing "unlink_visibility_verify" "$(time_elapsed_ms "$ts_uvverify")"

# Global count should be zero
remaining=$(ls "$TESTDIR"/node*_file* 2>/dev/null | wc -l)
remaining=$(echo "$remaining" | tr -d ' ')
assert_equals "0" "$remaining" "No files remain after deletion"

# Barrier: all verified
barrier_signal "uv_verify"
barrier_wait "uv_verify" "$TOTAL_NODES"

test_end
