#!/bin/bash
# Single-node test: symlinks — create, read, follow, remove
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "symlink"

TESTDIR="${TEST_DIR}/symlink"
mkdir -p "$TESTDIR"
add_cleanup "rm -rf $TESTDIR"

# Create a target file
echo "target content" > "$TESTDIR/target.txt"

# Create symlink
ln -s "$TESTDIR/target.txt" "$TESTDIR/link.txt"

# Verify link exists
if [ -L "$TESTDIR/link.txt" ]; then
    assert_true "Symlink is a symbolic link"
else
    test_fail "link.txt is not a symbolic link"
fi

# Read through symlink
content=$(cat "$TESTDIR/link.txt")
assert_equals "target content" "$content" "Read through symlink"

# Readlink
target=$(readlink "$TESTDIR/link.txt")
assert_equals "$TESTDIR/target.txt" "$target" "readlink returns target path"

# Stat on symlink (without -L, should show symlink type)
ftype=$(stat -c%F "$TESTDIR/link.txt")
assert_equals "symbolic link" "$ftype" "stat shows symbolic link type"

# Stat -L (follow symlink)
ftype=$(stat -L -c%F "$TESTDIR/link.txt")
assert_equals "regular file" "$ftype" "stat -L shows regular file"

# Write through symlink
echo "modified through link" > "$TESTDIR/link.txt"
content=$(cat "$TESTDIR/target.txt")
assert_equals "modified through link" "$content" "Write through symlink modifies target"

# Symlink to directory
mkdir "$TESTDIR/realdir"
touch "$TESTDIR/realdir/file_in_dir"
ln -s "$TESTDIR/realdir" "$TESTDIR/dirlink"
assert_file_exists "$TESTDIR/dirlink/file_in_dir" "Access file through dir symlink"

# Remove symlink (target should survive)
rm "$TESTDIR/link.txt"
assert_file_not_exists "$TESTDIR/link.txt" "Symlink removed"
assert_file_exists "$TESTDIR/target.txt" "Target survives symlink removal"

# Dangling symlink
ln -s "$TESTDIR/nonexistent" "$TESTDIR/dangling"
if [ -L "$TESTDIR/dangling" ]; then
    assert_true "Dangling symlink exists as link"
else
    test_fail "Dangling symlink not created"
fi
if [ -e "$TESTDIR/dangling" ]; then
    test_fail "Dangling symlink should not resolve"
else
    assert_true "Dangling symlink correctly does not resolve"
fi

# Relative symlink
echo "relative target" > "$TESTDIR/rel_target"
ln -s "rel_target" "$TESTDIR/rel_link"
content=$(cat "$TESTDIR/rel_link")
assert_equals "relative target" "$content" "Relative symlink works"

test_end
