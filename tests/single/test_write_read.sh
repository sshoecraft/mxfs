#!/bin/bash
# Single-node test: write data, read it back, verify integrity
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "write_read"

TESTDIR="${TEST_DIR}/write_read"
mkdir -p "$TESTDIR"
add_cleanup "rm -rf $TESTDIR"

# Simple echo write and read
echo "hello world" > "$TESTDIR/simple.txt"
content=$(cat "$TESTDIR/simple.txt")
assert_equals "hello world" "$content" "Simple write/read"

# Binary-safe: write known bytes with dd
dd if=/dev/urandom of="$TESTDIR/random_1k" bs=1024 count=1 2>/dev/null
sz=$(stat -c%s "$TESTDIR/random_1k")
assert_equals "1024" "$sz" "1K random file size"

# Write and verify with md5
dd if=/dev/urandom of="/tmp/mxfs_test_src" bs=4096 count=10 2>/dev/null
cp "/tmp/mxfs_test_src" "$TESTDIR/checksum_test"
expected_md5=$(md5sum "/tmp/mxfs_test_src" | awk '{print $1}')
assert_md5 "$expected_md5" "$TESTDIR/checksum_test" "40K file md5 matches"
rm -f "/tmp/mxfs_test_src"

# Append
echo "line1" > "$TESTDIR/append.txt"
echo "line2" >> "$TESTDIR/append.txt"
echo "line3" >> "$TESTDIR/append.txt"
linecount=$(wc -l < "$TESTDIR/append.txt")
assert_equals "3" "$linecount" "Append produces 3 lines"

content=$(cat "$TESTDIR/append.txt")
assert_contains "$content" "line1" "Append contains line1"
assert_contains "$content" "line2" "Append contains line2"
assert_contains "$content" "line3" "Append contains line3"

# Overwrite
echo "original" > "$TESTDIR/overwrite.txt"
echo "replaced" > "$TESTDIR/overwrite.txt"
content=$(cat "$TESTDIR/overwrite.txt")
assert_equals "replaced" "$content" "Overwrite replaces content"

# Write with specific offset (dd seek)
dd if=/dev/zero of="$TESTDIR/sparse" bs=1 count=1 seek=4095 2>/dev/null
sz=$(stat -c%s "$TESTDIR/sparse")
assert_equals "4096" "$sz" "Sparse file size correct"

# Read partial (head)
for i in $(seq 1 100); do
    echo "line_${i}"
done > "$TESTDIR/hundred_lines.txt"
first=$(head -1 "$TESTDIR/hundred_lines.txt")
assert_equals "line_1" "$first" "head reads first line"
last=$(tail -1 "$TESTDIR/hundred_lines.txt")
assert_equals "line_100" "$last" "tail reads last line"

test_end
