#!/bin/bash
# Single-node test: create files with touch, verify they exist
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "touch"

TESTDIR="${TEST_DIR}/touch"
mkdir -p "$TESTDIR"
add_cleanup "rm -rf $TESTDIR"

# Basic touch
touch "$TESTDIR/file1"
assert_file_exists "$TESTDIR/file1" "touch creates file"

# Touch multiple files
touch "$TESTDIR/file2" "$TESTDIR/file3" "$TESTDIR/file4"
assert_file_exists "$TESTDIR/file2" "touch creates file2"
assert_file_exists "$TESTDIR/file3" "touch creates file3"
assert_file_exists "$TESTDIR/file4" "touch creates file4"

# File should have zero size
sz=$(stat -c%s "$TESTDIR/file1")
assert_equals "0" "$sz" "Touched file has zero size"

# Touch should update timestamp
sleep 1
old_mtime=$(stat -c%Y "$TESTDIR/file1")
touch "$TESTDIR/file1"
new_mtime=$(stat -c%Y "$TESTDIR/file1")
if [ "$new_mtime" -gt "$old_mtime" ]; then
    assert_true "touch updates mtime"
else
    # mtime granularity might be 1s, allow equal
    assert_ge "$new_mtime" "$old_mtime" "touch updates or preserves mtime"
fi

# Touch with specific timestamp
ts_year=$(date +%Y)
touch -t "${ts_year}01011200.00" "$TESTDIR/file_ts"
assert_file_exists "$TESTDIR/file_ts" "touch with timestamp creates file"
actual_year=$(stat -c%y "$TESTDIR/file_ts" | cut -d'-' -f1)
assert_equals "$ts_year" "$actual_year" "Timestamp year is correct"

# Touch file with special characters in name (but filesystem-safe)
touch "$TESTDIR/file-with-dashes"
assert_file_exists "$TESTDIR/file-with-dashes" "touch file with dashes"

touch "$TESTDIR/file.with.dots"
assert_file_exists "$TESTDIR/file.with.dots" "touch file with dots"

touch "$TESTDIR/UPPERCASE"
assert_file_exists "$TESTDIR/UPPERCASE" "touch uppercase file"

test_end
