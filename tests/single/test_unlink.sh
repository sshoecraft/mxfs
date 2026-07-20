#!/bin/bash
# Single-node test: unlink (rm) files, rmdir directories
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "unlink"

TESTDIR="${TEST_DIR}/unlink"
mkdir -p "$TESTDIR"
add_cleanup "rm -rf $TESTDIR"

# Basic unlink
touch "$TESTDIR/delete_me"
assert_file_exists "$TESTDIR/delete_me" "File created"
rm "$TESTDIR/delete_me"
assert_file_not_exists "$TESTDIR/delete_me" "File removed after rm"

# Unlink file with content
echo "has content" > "$TESTDIR/with_data"
rm "$TESTDIR/with_data"
assert_file_not_exists "$TESTDIR/with_data" "File with data removed"

# Unlink multiple files
for i in $(seq 1 10); do
    touch "$TESTDIR/batch_${i}"
done
for i in $(seq 1 10); do
    assert_file_exists "$TESTDIR/batch_${i}" "Batch file ${i} exists"
done
rm "$TESTDIR"/batch_*
for i in $(seq 1 10); do
    assert_file_not_exists "$TESTDIR/batch_${i}" "Batch file ${i} removed"
done

# rmdir on empty directory
mkdir "$TESTDIR/empty_dir"
rmdir "$TESTDIR/empty_dir"
assert_dir_not_exists "$TESTDIR/empty_dir" "Empty dir removed by rmdir"

# rmdir should fail on non-empty directory
mkdir "$TESTDIR/nonempty"
touch "$TESTDIR/nonempty/child"
if rmdir "$TESTDIR/nonempty" 2>/dev/null; then
    test_fail "rmdir should fail on non-empty directory"
else
    assert_true "rmdir correctly fails on non-empty dir"
fi
rm -rf "$TESTDIR/nonempty"

# rm -r on directory tree
mkdir -p "$TESTDIR/tree/a/b/c"
touch "$TESTDIR/tree/a/file1" "$TESTDIR/tree/a/b/file2" "$TESTDIR/tree/a/b/c/file3"
rm -rf "$TESTDIR/tree"
assert_dir_not_exists "$TESTDIR/tree" "rm -rf removes entire tree"

# Unlink then recreate
touch "$TESTDIR/recreate"
rm "$TESTDIR/recreate"
touch "$TESTDIR/recreate"
assert_file_exists "$TESTDIR/recreate" "File recreated after unlink"

# Verify inode is reused or new (just verify it works)
ino=$(stat -c%i "$TESTDIR/recreate")
assert_nonzero "$ino" "Recreated file has valid inode"

test_end
