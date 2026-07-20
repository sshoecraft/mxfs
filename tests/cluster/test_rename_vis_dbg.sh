#!/bin/bash
# Cluster test: rename on one node, verify visibility on all others
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "rename_vis_dbg"

# Use a DISTINCT work dir + barrier namespace from test_rename_visibility.
# Both tests run in the same cluster phase on the same mount; sharing
# .mxfs_test/rename_visibility + rv_* barriers meant whichever ran second
# inherited the first's leftover after-files and already-signalled barriers
# → phase desync + 2x120s barrier timeouts (the run_tests per-test cleanup
# keys on ${test_name} and never matched these names).  Isolate this debug
# variant so the two tests cannot contaminate each other.
TESTDIR="$MOUNT_POINT/.mxfs_test/rename_vis_dbg"
mkdir -p "$TESTDIR" 2>/dev/null

RENAMES_PER_NODE=20

# Phase 1: Each node creates files to rename
log_info "Node ${NODE_ID}: creating ${RENAMES_PER_NODE} files..."
for i in $(seq 1 $RENAMES_PER_NODE); do
    echo "content_${NODE_ID}_${i}" > "$TESTDIR/node${NODE_ID}_before_${i}"
done

# Barrier: files created
barrier_signal "rvd_create"
barrier_wait "rvd_create" "$TOTAL_NODES"
sleep 1

# Phase 2: Each node renames its files
log_info "Node ${NODE_ID}: renaming files..."
ts_rename=$(time_op)
for i in $(seq 1 $RENAMES_PER_NODE); do
    mv "$TESTDIR/node${NODE_ID}_before_${i}" "$TESTDIR/node${NODE_ID}_after_${i}"
done
sync
log_timing "rename_${RENAMES_PER_NODE}_files" "$(time_elapsed_ms "$ts_rename")"

# Barrier: renames done
barrier_signal "rvd_rename"
barrier_wait "rvd_rename" "$TOTAL_NODES"
sleep 2

# Phase 3: Each node verifies all renames are visible
ts_rvverify=$(time_op)
for n in $(seq 1 "$TOTAL_NODES"); do
    for i in $(seq 1 $RENAMES_PER_NODE); do
        assert_file_not_exists "$TESTDIR/node${n}_before_${i}" "Old name gone: node${n}_before_${i}"
        assert_file_exists "$TESTDIR/node${n}_after_${i}" "New name exists: node${n}_after_${i}"

        # Verify content preserved
        content=$(cat "$TESTDIR/node${n}_after_${i}")
        if [ "$content" != "content_${n}_${i}" ]; then
            __sz=$(stat -c %s "$TESTDIR/node${n}_after_${i}" 2>/dev/null)
            __ino=$(stat -c %i "$TESTDIR/node${n}_after_${i}" 2>/dev/null)
            log_info "DBG-EMPTY reader=node${NODE_ID} target=node${n}_after_${i} statsize=${__sz} ino=${__ino} content=[${content}]"
        fi
        assert_equals "content_${n}_${i}" "$content" "Content preserved in node${n}_after_${i}"
    done
done
log_timing "rename_visibility_verify" "$(time_elapsed_ms "$ts_rvverify")"

# Barrier: verification done
barrier_signal "rvd_verify"
barrier_wait "rvd_verify" "$TOTAL_NODES"

test_end
