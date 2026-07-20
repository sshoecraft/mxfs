#!/bin/bash
# Cluster test: concurrent directory operations from multiple nodes
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "dir_stress"

TESTDIR="$MOUNT_POINT/.mxfs_test/dir_stress"
mkdir -p "$TESTDIR" 2>/dev/null

DIRS_PER_NODE=20
FILES_PER_DIR=10

# Barrier: synchronize start
barrier_signal "ds_ready"
barrier_wait "ds_ready" "$TOTAL_NODES"

# Phase 1: Each node creates dirs with files inside
log_info "Node ${NODE_ID}: creating ${DIRS_PER_NODE} dirs with ${FILES_PER_DIR} files each..."
ts_dscreate=$(time_op)
for d in $(seq 1 $DIRS_PER_NODE); do
    dir="$TESTDIR/node${NODE_ID}_dir${d}"
    mkdir "$dir" || {
        test_fail "Failed to create dir ${dir}"
        continue
    }
    for f in $(seq 1 $FILES_PER_DIR); do
        echo "n${NODE_ID}_d${d}_f${f}" > "${dir}/file${f}"
    done
done
elapsed_create=$(time_elapsed_ms "$ts_dscreate")
log_timing "create_${DIRS_PER_NODE}dirs_${FILES_PER_DIR}files" "$elapsed_create"
total_ops=$((DIRS_PER_NODE * (1 + FILES_PER_DIR)))
if [ "$elapsed_create" -gt 0 ]; then
    ops_sec=$((total_ops * 1000 / elapsed_create))
    log_timing "create_ops_per_sec" "$ops_sec"
fi

# Barrier: creation done
barrier_signal "ds_create_done"
barrier_wait "ds_create_done" "$TOTAL_NODES"
sleep 2

# Phase 2: Each node verifies it can read other nodes' directories
read_node=$(( (NODE_ID % TOTAL_NODES) + 1 ))
log_info "Node ${NODE_ID}: verifying node ${read_node} directories..."
for d in $(seq 1 $DIRS_PER_NODE); do
    dir="$TESTDIR/node${read_node}_dir${d}"
    assert_dir_exists "$dir" "Dir node${read_node}_dir${d} visible"
    file_count=$(ls "$dir" 2>/dev/null | wc -l)
    file_count=$(echo "$file_count" | tr -d ' ')
    assert_equals "$FILES_PER_DIR" "$file_count" "Dir node${read_node}_dir${d} has ${FILES_PER_DIR} files"
done

# Phase 3: Each node renames its own dirs
log_info "Node ${NODE_ID}: renaming directories..."
ts_dsrename=$(time_op)
for d in $(seq 1 $DIRS_PER_NODE); do
    mv "$TESTDIR/node${NODE_ID}_dir${d}" "$TESTDIR/node${NODE_ID}_renamed${d}"
done
log_timing "rename_${DIRS_PER_NODE}_dirs" "$(time_elapsed_ms "$ts_dsrename")"

# Barrier: renames done
barrier_signal "ds_rename_done"
barrier_wait "ds_rename_done" "$TOTAL_NODES"
sleep 2

# Phase 4: Verify renames visible from other nodes
log_info "Node ${NODE_ID}: verifying renames on node ${read_node}..."
for d in $(seq 1 $DIRS_PER_NODE); do
    assert_dir_not_exists "$TESTDIR/node${read_node}_dir${d}" "Old name gone: node${read_node}_dir${d}"
    assert_dir_exists "$TESTDIR/node${read_node}_renamed${d}" "New name exists: node${read_node}_renamed${d}"
done

# Node 1: verify total dir count
if [ "$NODE_ID" = "1" ]; then
    expected=$((TOTAL_NODES * DIRS_PER_NODE))
    actual=$(find "$TESTDIR" -maxdepth 1 -type d -name 'node*_renamed*' | wc -l)
    actual=$(echo "$actual" | tr -d ' ')
    assert_equals "$expected" "$actual" "Total renamed dir count"
fi

# Barrier: all done
barrier_signal "ds_verify"
barrier_wait "ds_verify" "$TOTAL_NODES"

test_end
