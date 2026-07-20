#!/bin/bash
# Single-node test: deeply nested directories, tree operations
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "nested_dirs"

TESTDIR="${TEST_DIR}/nested_dirs"
mkdir -p "$TESTDIR"
add_cleanup "rm -rf $TESTDIR"

# Deep nesting (20 levels)
DEPTH=20
log_info "Creating ${DEPTH}-level deep directory tree..."
path="$TESTDIR"
for i in $(seq 1 $DEPTH); do
    path="${path}/level_${i}"
done
mkdir -p "$path"
assert_dir_exists "$path" "20-level deep directory exists"

# Write file at bottom
echo "deep file" > "${path}/deepfile.txt"
content=$(cat "${path}/deepfile.txt")
assert_equals "deep file" "$content" "File at depth 20 is readable"

# Wide tree (50 dirs at same level)
WIDTH=50
log_info "Creating ${WIDTH} sibling directories..."
for i in $(seq 1 $WIDTH); do
    mkdir "$TESTDIR/wide_$(printf '%03d' $i)"
    touch "$TESTDIR/wide_$(printf '%03d' $i)/marker"
done

dir_count=$(ls -d "$TESTDIR"/wide_* | wc -l)
dir_count=$(echo "$dir_count" | tr -d ' ')
assert_equals "$WIDTH" "$dir_count" "${WIDTH} sibling directories created"

# Verify marker files
for i in 1 25 50; do
    assert_file_exists "$TESTDIR/wide_$(printf '%03d' $i)/marker" "Marker in wide_$(printf '%03d' $i)"
done

# Tree with files at every level
log_info "Creating tree with files at every level..."
path="$TESTDIR/mixed"
for i in $(seq 1 10); do
    path="${path}/d${i}"
    mkdir -p "$path"
    echo "level_${i}" > "${path}/data.txt"
done

# Verify files at multiple levels
path="$TESTDIR/mixed"
for i in $(seq 1 10); do
    path="${path}/d${i}"
    content=$(cat "${path}/data.txt")
    assert_equals "level_${i}" "$content" "File at level ${i} correct"
done

# Rename a mid-level directory
mv "$TESTDIR/mixed/d1/d2/d3" "$TESTDIR/mixed/d1/d2/d3_renamed"
assert_dir_not_exists "$TESTDIR/mixed/d1/d2/d3" "Old mid-level dir gone"
assert_dir_exists "$TESTDIR/mixed/d1/d2/d3_renamed" "Renamed mid-level dir exists"
assert_file_exists "$TESTDIR/mixed/d1/d2/d3_renamed/d4/data.txt" "Deep file accessible through renamed dir"

# rm -rf on wide tree
rm -rf "$TESTDIR/wide_"*
remaining=$(ls -d "$TESTDIR"/wide_* 2>/dev/null | wc -l)
remaining=$(echo "$remaining" | tr -d ' ')
assert_equals "0" "$remaining" "Wide tree fully removed"

test_end
