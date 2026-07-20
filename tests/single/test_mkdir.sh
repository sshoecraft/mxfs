#!/bin/bash
# Single-node test: create directories, verify they exist and have correct attributes
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "mkdir"

TESTDIR="${TEST_DIR}/mkdir"
mkdir -p "$TESTDIR"
add_cleanup "rm -rf $TESTDIR"

# Basic mkdir
mkdir "$TESTDIR/dir1"
assert_dir_exists "$TESTDIR/dir1" "mkdir creates directory"

# mkdir -p (nested)
mkdir -p "$TESTDIR/a/b/c/d"
assert_dir_exists "$TESTDIR/a" "mkdir -p creates parent a"
assert_dir_exists "$TESTDIR/a/b" "mkdir -p creates parent b"
assert_dir_exists "$TESTDIR/a/b/c" "mkdir -p creates parent c"
assert_dir_exists "$TESTDIR/a/b/c/d" "mkdir -p creates leaf d"

# Directory should show as directory type
ftype=$(stat -c%F "$TESTDIR/dir1")
assert_equals "directory" "$ftype" "stat shows directory type"

# rmdir
rmdir "$TESTDIR/dir1"
assert_dir_not_exists "$TESTDIR/dir1" "rmdir removes directory"

# rmdir on nested (leaf only)
rmdir "$TESTDIR/a/b/c/d"
assert_dir_not_exists "$TESTDIR/a/b/c/d" "rmdir removes nested leaf"
assert_dir_exists "$TESTDIR/a/b/c" "rmdir preserves parent"

# mkdir with mode
mkdir -m 755 "$TESTDIR/mode755"
perms=$(stat -c%a "$TESTDIR/mode755")
assert_equals "755" "$perms" "mkdir -m 755 sets permissions"

mkdir -m 700 "$TESTDIR/mode700"
perms=$(stat -c%a "$TESTDIR/mode700")
assert_equals "700" "$perms" "mkdir -m 700 sets permissions"

# Multiple directories at once
mkdir "$TESTDIR/multi1" "$TESTDIR/multi2" "$TESTDIR/multi3"
assert_dir_exists "$TESTDIR/multi1" "mkdir multi1"
assert_dir_exists "$TESTDIR/multi2" "mkdir multi2"
assert_dir_exists "$TESTDIR/multi3" "mkdir multi3"

# Directory link count (. and ..)
nlink=$(stat -c%h "$TESTDIR/multi1")
assert_equals "2" "$nlink" "Empty dir has link count 2"

test_end
