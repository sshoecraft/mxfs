#!/bin/bash
# Single-node test: large file write/read with integrity check
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "large_file"

TESTDIR="${TEST_DIR}/large_file"
mkdir -p "$TESTDIR"
add_cleanup "rm -rf $TESTDIR"

# 1MB file
log_info "Writing 1MB file..."
dd if=/dev/urandom of="/tmp/mxfs_1m_src" bs=1M count=1 2>/dev/null
cp "/tmp/mxfs_1m_src" "$TESTDIR/file_1m"
sync
expected=$(md5sum "/tmp/mxfs_1m_src" | awk '{print $1}')
assert_md5 "$expected" "$TESTDIR/file_1m" "1MB file integrity"
rm -f "/tmp/mxfs_1m_src"

sz=$(stat -c%s "$TESTDIR/file_1m")
assert_equals "1048576" "$sz" "1MB file size"

# 10MB file
log_info "Writing 10MB file..."
dd if=/dev/urandom of="/tmp/mxfs_10m_src" bs=1M count=10 2>/dev/null
cp "/tmp/mxfs_10m_src" "$TESTDIR/file_10m"
sync
expected=$(md5sum "/tmp/mxfs_10m_src" | awk '{print $1}')
assert_md5 "$expected" "$TESTDIR/file_10m" "10MB file integrity"
rm -f "/tmp/mxfs_10m_src"

sz=$(stat -c%s "$TESTDIR/file_10m")
assert_equals "10485760" "$sz" "10MB file size"

# 100MB file
log_info "Writing 100MB file..."
dd if=/dev/urandom of="/tmp/mxfs_100m_src" bs=1M count=100 2>/dev/null
cp "/tmp/mxfs_100m_src" "$TESTDIR/file_100m"
sync
expected=$(md5sum "/tmp/mxfs_100m_src" | awk '{print $1}')
assert_md5 "$expected" "$TESTDIR/file_100m" "100MB file integrity"
rm -f "/tmp/mxfs_100m_src"

sz=$(stat -c%s "$TESTDIR/file_100m")
assert_equals "104857600" "$sz" "100MB file size"

# Re-read after sync to verify persistence
log_info "Re-reading files after sync..."
sync
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
sz=$(stat -c%s "$TESTDIR/file_100m")
assert_equals "104857600" "$sz" "100MB file persists after cache drop"

test_end
