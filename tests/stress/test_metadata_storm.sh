#!/bin/bash
# Stress test: rapid metadata operations (stat, chmod, touch) from all nodes
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "metadata_storm"

TESTDIR="$MOUNT_POINT/.mxfs_test/metadata_storm"
mkdir -p "$TESTDIR" 2>/dev/null

SHARED_FILES=50
ITERATIONS=20

# Node 1 creates the shared files
if [ "$NODE_ID" = "1" ]; then
    log_info "Node 1: creating ${SHARED_FILES} shared files..."
    for i in $(seq 1 $SHARED_FILES); do
        echo "metadata_test_${i}" > "$TESTDIR/shared_$(printf '%03d' $i)"
    done
fi

# Barrier: files created
barrier_signal "ms_create"
barrier_wait "ms_create" "$TOTAL_NODES"
sleep 1

# All nodes hammer metadata operations on the shared files
log_info "Node ${NODE_ID}: ${ITERATIONS} rounds of metadata ops on ${SHARED_FILES} files..."
start_time=$(date +%s)

for round in $(seq 1 $ITERATIONS); do
    for i in $(seq 1 $SHARED_FILES); do
        file="$TESTDIR/shared_$(printf '%03d' $i)"

        # stat
        stat -c%s "$file" > /dev/null 2>&1 || {
            test_fail "stat failed: round ${round} file ${i}"
        }

        # touch (update mtime)
        touch "$file" 2>/dev/null || true

        # chmod
        chmod 644 "$file" 2>/dev/null || true

        # readdir (ls the parent)
        if [ "$i" -eq 1 ]; then
            ls "$TESTDIR" > /dev/null 2>&1 || true
        fi
    done
done

end_time=$(date +%s)
elapsed=$((end_time - start_time))
total_ops=$((ITERATIONS * SHARED_FILES * 3))
log_info "Node ${NODE_ID}: ${total_ops} metadata ops in ${elapsed}s ($(( total_ops / (elapsed + 1) )) ops/s)"

# Barrier: storm done
barrier_signal "ms_done"
barrier_wait "ms_done" "$TOTAL_NODES"

# Verify files still intact
for i in $(seq 1 $SHARED_FILES); do
    assert_file_exists "$TESTDIR/shared_$(printf '%03d' $i)" "File shared_$(printf '%03d' $i) still exists"
done

# Barrier: verify done
barrier_signal "ms_verify"
barrier_wait "ms_verify" "$TOTAL_NODES"

test_end
