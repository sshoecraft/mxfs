#!/bin/bash
# Cluster test: large file write on one node, verify integrity from all nodes
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "large_file_integrity"

TESTDIR="$MOUNT_POINT/.mxfs_test/large_file_integrity"
mkdir -p "$TESTDIR" 2>/dev/null

FILE_SIZE_MB=10

# Node 1 writes the large file
if [ "$NODE_ID" = "1" ]; then
    log_info "Node 1: writing ${FILE_SIZE_MB}MB file..."
    ts_lfiwrite=$(time_op)
    dd if=/dev/urandom of="/tmp/mxfs_lfi_src" bs=1M count=$FILE_SIZE_MB 2>/dev/null
    cp "/tmp/mxfs_lfi_src" "$TESTDIR/bigfile"
    sync
    elapsed_w=$(time_elapsed_ms "$ts_lfiwrite")
    log_timing "write_${FILE_SIZE_MB}MB" "$elapsed_w"
    # Calculate MB/s
    if [ "$elapsed_w" -gt 0 ]; then
        mbps=$(( FILE_SIZE_MB * 1000 / elapsed_w ))
        log_timing "write_MBps" "$mbps"
    fi
    md5sum "/tmp/mxfs_lfi_src" | awk '{print $1}' > "$TESTDIR/bigfile.md5"
    rm -f "/tmp/mxfs_lfi_src"
    log_info "Node 1: write complete, md5=$(cat "$TESTDIR/bigfile.md5")"
fi

# Barrier: writer done
barrier_signal "lfi_write"
barrier_wait "lfi_write" "$TOTAL_NODES"
sleep 2

# All nodes read and verify
log_info "Node ${NODE_ID}: reading and verifying ${FILE_SIZE_MB}MB file..."
ts_lfiread=$(time_op)
expected_md5=$(cat "$TESTDIR/bigfile.md5")

# Verify size
sz=$(stat -c%s "$TESTDIR/bigfile")
expected_sz=$((FILE_SIZE_MB * 1048576))
assert_equals "$expected_sz" "$sz" "Node ${NODE_ID}: file size is ${FILE_SIZE_MB}MB"

# Verify checksum
actual_md5=$(md5sum "$TESTDIR/bigfile" | awk '{print $1}')
assert_equals "$expected_md5" "$actual_md5" "Node ${NODE_ID}: large file md5 matches"
elapsed_r=$(time_elapsed_ms "$ts_lfiread")
log_timing "read_verify_${FILE_SIZE_MB}MB" "$elapsed_r"
if [ "$elapsed_r" -gt 0 ]; then
    mbps=$(( FILE_SIZE_MB * 1000 / elapsed_r ))
    log_timing "read_MBps" "$mbps"
fi

# Barrier: all verified
barrier_signal "lfi_verify"
barrier_wait "lfi_verify" "$TOTAL_NODES"

test_end
