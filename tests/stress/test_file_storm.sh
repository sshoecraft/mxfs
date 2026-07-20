#!/bin/bash
# Stress test: all nodes create/delete files as fast as possible
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "file_storm"

TESTDIR="$MOUNT_POINT/.mxfs_test/file_storm"
mkdir -p "$TESTDIR/node${NODE_ID}" 2>/dev/null

ROUNDS=5
FILES_PER_ROUND=200

# Barrier: synchronize start
barrier_signal "fs_ready"
barrier_wait "fs_ready" "$TOTAL_NODES"

start_time=$(date +%s)

for round in $(seq 1 $ROUNDS); do
    log_info "Node ${NODE_ID}: round ${round}/${ROUNDS} — creating ${FILES_PER_ROUND} files..."

    # Create phase
    for i in $(seq 1 $FILES_PER_ROUND); do
        echo "r${round}_f${i}" > "$TESTDIR/node${NODE_ID}/r${round}_file${i}" || {
            test_fail "Create failed: round ${round} file ${i}"
            break
        }
    done

    # Verify phase
    count=$(ls "$TESTDIR/node${NODE_ID}"/r${round}_file* 2>/dev/null | wc -l)
    count=$(echo "$count" | tr -d ' ')
    assert_equals "$FILES_PER_ROUND" "$count" "Round ${round}: created ${FILES_PER_ROUND} files"

    # Delete phase (previous round if not first)
    if [ "$round" -gt 1 ]; then
        prev=$((round - 1))
        rm -f "$TESTDIR/node${NODE_ID}"/r${prev}_file*
    fi
done

# Delete last round
rm -f "$TESTDIR/node${NODE_ID}"/r${ROUNDS}_file*

end_time=$(date +%s)
elapsed=$((end_time - start_time))
total_ops=$((ROUNDS * FILES_PER_ROUND * 2))  # create + delete
log_info "Node ${NODE_ID}: ${total_ops} ops in ${elapsed}s"

# Verify clean
remaining=$(ls "$TESTDIR/node${NODE_ID}" 2>/dev/null | wc -l)
remaining=$(echo "$remaining" | tr -d ' ')
assert_equals "0" "$remaining" "All files cleaned up"

# Barrier: storm done
barrier_signal "fs_done"
barrier_wait "fs_done" "$TOTAL_NODES"

# Node 1: report aggregate stats
if [ "$NODE_ID" = "1" ]; then
    log_info "File storm complete: ${TOTAL_NODES} nodes x ${total_ops} ops = $((TOTAL_NODES * total_ops)) total ops"
fi

test_end
