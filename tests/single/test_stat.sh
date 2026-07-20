#!/bin/bash
# Single-node test: stat operations — size, times, permissions, types
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "stat"

TESTDIR="${TEST_DIR}/stat"
mkdir -p "$TESTDIR"
add_cleanup "rm -rf $TESTDIR"

# Create a file with known content
echo "stat test content" > "$TESTDIR/statfile"

# Size
sz=$(stat -c%s "$TESTDIR/statfile")
assert_equals "18" "$sz" "File size correct (17 chars + newline)"

# File type
ftype=$(stat -c%F "$TESTDIR/statfile")
assert_equals "regular file" "$ftype" "Type is regular file"

# Directory type
mkdir "$TESTDIR/subdir"
ftype=$(stat -c%F "$TESTDIR/subdir")
assert_equals "directory" "$ftype" "Type is directory"

# Permissions
chmod 644 "$TESTDIR/statfile"
perms=$(stat -c%a "$TESTDIR/statfile")
assert_equals "644" "$perms" "Permissions 644"

chmod 600 "$TESTDIR/statfile"
perms=$(stat -c%a "$TESTDIR/statfile")
assert_equals "600" "$perms" "Permissions 600"

chmod 755 "$TESTDIR/statfile"
perms=$(stat -c%a "$TESTDIR/statfile")
assert_equals "755" "$perms" "Permissions 755"

# Link count
nlink=$(stat -c%h "$TESTDIR/statfile")
assert_equals "1" "$nlink" "Regular file link count is 1"

# Inode number should be non-zero
ino=$(stat -c%i "$TESTDIR/statfile")
assert_nonzero "$ino" "Inode number is nonzero"

# Timestamps exist and are reasonable (after 2024)
mtime=$(stat -c%Y "$TESTDIR/statfile")
assert_ge "$mtime" "1704067200" "mtime is after 2024-01-01"

# statfs
avail=$(stat -f -c%a "$TESTDIR/statfile")
assert_nonzero "$avail" "Available blocks nonzero"

bsize=$(stat -f -c%S "$TESTDIR/statfile")
assert_nonzero "$bsize" "Block size nonzero"

# Stat after modification
echo "more data" >> "$TESTDIR/statfile"
new_sz=$(stat -c%s "$TESTDIR/statfile")
assert_ge "$new_sz" "$sz" "Size grows after append"

test_end
