#!/bin/bash
# Stress test: mixed workload — files, dirs, writes, reads, renames, deletes
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "mixed_workload"

TESTDIR="$MOUNT_POINT/.mxfs_test/mixed_workload"
MYDIR="$TESTDIR/node${NODE_ID}"
mkdir -p "$MYDIR" 2>/dev/null

ITERATIONS=10
FILES_PER_ITER=20

# Barrier: synchronize start
barrier_signal "mw_ready"
barrier_wait "mw_ready" "$TOTAL_NODES"

start_time=$(date +%s)

for round in $(seq 1 $ITERATIONS); do
    log_info "Node ${NODE_ID}: round ${round}/${ITERATIONS}..."

    # 1. Create a subdirectory
    subdir="$MYDIR/round${round}"
    mkdir -p "$subdir"

    # 2. Create files with data
    for i in $(seq 1 $FILES_PER_ITER); do
        echo "node${NODE_ID}_round${round}_file${i}_$(date +%s%N)" > "$subdir/file${i}"
    done

    # 3. Read back a few files
    for i in 1 5 10 15 20; do
        if [ -f "$subdir/file${i}" ]; then
            cat "$subdir/file${i}" > /dev/null
        fi
    done

    # 4. Stat all files
    for i in $(seq 1 $FILES_PER_ITER); do
        stat -c%s "$subdir/file${i}" > /dev/null 2>&1
    done

    # 5. Rename half the files
    for i in $(seq 1 $((FILES_PER_ITER / 2))); do
        mv "$subdir/file${i}" "$subdir/renamed${i}" 2>/dev/null || true
    done

    # 6. Delete the renamed files
    for i in $(seq 1 $((FILES_PER_ITER / 2))); do
        rm -f "$subdir/renamed${i}"
    done

    # 7. Verify remaining files
    remaining=$(ls "$subdir" 2>/dev/null | wc -l)
    remaining=$(echo "$remaining" | tr -d ' ')
    expected=$((FILES_PER_ITER / 2))
    assert_equals "$expected" "$remaining" "Round ${round}: ${expected} files remain"

    # 8. Cross-read: peek at another node's data (if available)
    other_node=$(( (NODE_ID % TOTAL_NODES) + 1 ))
    if [ "$round" -gt 1 ]; then
        other_dir="$TESTDIR/node${other_node}/round$((round - 1))"
        if [ -d "$other_dir" ]; then
            ls "$other_dir" > /dev/null 2>&1 || true
        fi
    fi
done

end_time=$(date +%s)
elapsed=$((end_time - start_time))
log_info "Node ${NODE_ID}: mixed workload done in ${elapsed}s"

# Barrier: workload done
barrier_signal "mw_done"
barrier_wait "mw_done" "$TOTAL_NODES"

# Final verification: check own directories
for round in $(seq 1 $ITERATIONS); do
    subdir="$MYDIR/round${round}"
    assert_dir_exists "$subdir" "Round ${round} dir exists"
done

# Barrier: verify done
barrier_signal "mw_verify"
barrier_wait "mw_verify" "$TOTAL_NODES"

test_end
