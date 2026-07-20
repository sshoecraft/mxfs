#!/bin/bash
# Stress test: create hundreds of directories across all nodes, with nested structure
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "many_dirs"

TESTDIR="$MOUNT_POINT/.mxfs_test/many_dirs"
mkdir -p "$TESTDIR" 2>/dev/null

DIRS_PER_NODE=100
NESTING_DEPTH=3

# Barrier: synchronize start
barrier_signal "md_ready"
barrier_wait "md_ready" "$TOTAL_NODES"

# Each node creates a tree of directories
log_info "Node ${NODE_ID}: creating ${DIRS_PER_NODE} directory trees (depth ${NESTING_DEPTH})..."
start_time=$(date +%s)

for d in $(seq 1 $DIRS_PER_NODE); do
    path="$TESTDIR/n${NODE_ID}_d${d}"
    for level in $(seq 1 $NESTING_DEPTH); do
        path="${path}/level${level}"
    done
    mkdir -p "$path" || {
        test_fail "Failed to create tree ${d}"
        continue
    }
    # Write a marker at the leaf
    echo "n${NODE_ID}_d${d}" > "${path}/marker"
done

end_time=$(date +%s)
elapsed=$((end_time - start_time))
log_info "Node ${NODE_ID}: created ${DIRS_PER_NODE} trees in ${elapsed}s"

# Barrier: creation done
barrier_signal "md_create"
barrier_wait "md_create" "$TOTAL_NODES"
sleep 2

# Verify own trees
for d in 1 25 50 75 100; do
    path="$TESTDIR/n${NODE_ID}_d${d}"
    for level in $(seq 1 $NESTING_DEPTH); do
        path="${path}/level${level}"
    done
    assert_file_exists "${path}/marker" "Tree ${d} leaf marker exists"
    content=$(cat "${path}/marker")
    assert_equals "n${NODE_ID}_d${d}" "$content" "Tree ${d} marker content"
done

# Cross-node visibility
other_node=$(( (NODE_ID % TOTAL_NODES) + 1 ))
path="$TESTDIR/n${other_node}_d1"
for level in $(seq 1 $NESTING_DEPTH); do
    path="${path}/level${level}"
done
assert_file_exists "${path}/marker" "Cross-node tree visible"

# Node 1: count top-level dirs
if [ "$NODE_ID" = "1" ]; then
    total_expected=$((TOTAL_NODES * DIRS_PER_NODE))
    total_actual=$(find "$TESTDIR" -maxdepth 1 -type d -name 'n*_d*' | wc -l)
    total_actual=$(echo "$total_actual" | tr -d ' ')
    assert_equals "$total_expected" "$total_actual" "Total top-level dirs: ${total_expected}"
fi

# Barrier: verify done
barrier_signal "md_verify"
barrier_wait "md_verify" "$TOTAL_NODES"

test_end
