#!/bin/bash
# Single-node test: rename (mv) files and directories
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "rename"

TESTDIR="${TEST_DIR}/rename"
mkdir -p "$TESTDIR"
add_cleanup "rm -rf $TESTDIR"

# Rename a file
echo "rename test" > "$TESTDIR/before.txt"
mv "$TESTDIR/before.txt" "$TESTDIR/after.txt"
assert_file_not_exists "$TESTDIR/before.txt" "Old name gone after rename"
assert_file_exists "$TESTDIR/after.txt" "New name exists after rename"
content=$(cat "$TESTDIR/after.txt")
assert_equals "rename test" "$content" "Content preserved after rename"

# Rename preserves inode (same filesystem)
echo "inode test" > "$TESTDIR/inode_src"
ino_before=$(stat -c%i "$TESTDIR/inode_src")
mv "$TESTDIR/inode_src" "$TESTDIR/inode_dst"
ino_after=$(stat -c%i "$TESTDIR/inode_dst")
assert_equals "$ino_before" "$ino_after" "Inode preserved on rename"

# Rename overwrite (mv to existing file replaces it)
echo "original" > "$TESTDIR/target.txt"
echo "replacement" > "$TESTDIR/source.txt"
mv "$TESTDIR/source.txt" "$TESTDIR/target.txt"
content=$(cat "$TESTDIR/target.txt")
assert_equals "replacement" "$content" "Rename overwrites target"
assert_file_not_exists "$TESTDIR/source.txt" "Source gone after overwrite rename"

# Rename a directory
mkdir "$TESTDIR/dir_before"
touch "$TESTDIR/dir_before/child.txt"
mv "$TESTDIR/dir_before" "$TESTDIR/dir_after"
assert_dir_not_exists "$TESTDIR/dir_before" "Old dir name gone"
assert_dir_exists "$TESTDIR/dir_after" "New dir name exists"
assert_file_exists "$TESTDIR/dir_after/child.txt" "Child preserved in renamed dir"

# Rename into a subdirectory
mkdir "$TESTDIR/subdir"
echo "move me" > "$TESTDIR/moveme.txt"
mv "$TESTDIR/moveme.txt" "$TESTDIR/subdir/"
assert_file_not_exists "$TESTDIR/moveme.txt" "File moved out of parent"
assert_file_exists "$TESTDIR/subdir/moveme.txt" "File landed in subdir"

# Cross-directory rename
mkdir -p "$TESTDIR/src_dir" "$TESTDIR/dst_dir"
echo "cross" > "$TESTDIR/src_dir/cross.txt"
mv "$TESTDIR/src_dir/cross.txt" "$TESTDIR/dst_dir/cross.txt"
assert_file_not_exists "$TESTDIR/src_dir/cross.txt" "File gone from src_dir"
assert_file_exists "$TESTDIR/dst_dir/cross.txt" "File in dst_dir"
content=$(cat "$TESTDIR/dst_dir/cross.txt")
assert_equals "cross" "$content" "Content preserved in cross-dir rename"

test_end
