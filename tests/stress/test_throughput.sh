#!/bin/bash
# Stress test: sustained throughput — each node writes large data, measures bandwidth
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "throughput"

TESTDIR="$MOUNT_POINT/.mxfs_test/throughput"
mkdir -p "$TESTDIR/node${NODE_ID}" 2>/dev/null

# Each node writes 50MB total (5 x 10MB files)
FILE_SIZE_MB=10
FILE_COUNT=5
TOTAL_MB=$((FILE_SIZE_MB * FILE_COUNT))

# Barrier: synchronize start
barrier_signal "tp_ready"
barrier_wait "tp_ready" "$TOTAL_NODES"

# Write phase
log_info "Node ${NODE_ID}: writing ${TOTAL_MB}MB (${FILE_COUNT} x ${FILE_SIZE_MB}MB)..."
write_start=$(date +%s%N)

for i in $(seq 1 $FILE_COUNT); do
    dd if=/dev/urandom of="$TESTDIR/node${NODE_ID}/data_${i}" bs=1M count=$FILE_SIZE_MB 2>/dev/null || {
        test_fail "Write failed: file ${i}"
    }
done
sync

write_end=$(date +%s%N)
write_ms=$(( (write_end - write_start) / 1000000 ))
write_mbps=$(awk "BEGIN {printf \"%.1f\", ${TOTAL_MB} / (${write_ms} / 1000.0)}")
log_info "Node ${NODE_ID}: write throughput: ${write_mbps} MB/s (${TOTAL_MB}MB in ${write_ms}ms)"

# Store write speed for reporting
echo "$write_mbps" > "$TESTDIR/node${NODE_ID}/write_mbps"

# Barrier: writes done
barrier_signal "tp_write"
barrier_wait "tp_write" "$TOTAL_NODES"
sleep 2

# Read phase — read own files
log_info "Node ${NODE_ID}: reading ${TOTAL_MB}MB..."
read_start=$(date +%s%N)

for i in $(seq 1 $FILE_COUNT); do
    dd if="$TESTDIR/node${NODE_ID}/data_${i}" of=/dev/null bs=1M 2>/dev/null || {
        test_fail "Read failed: file ${i}"
    }
done

read_end=$(date +%s%N)
read_ms=$(( (read_end - read_start) / 1000000 ))
read_mbps=$(awk "BEGIN {printf \"%.1f\", ${TOTAL_MB} / (${read_ms} / 1000.0)}")
log_info "Node ${NODE_ID}: read throughput: ${read_mbps} MB/s (${TOTAL_MB}MB in ${read_ms}ms)"

# Store read speed
echo "$read_mbps" > "$TESTDIR/node${NODE_ID}/read_mbps"

# Cross-read phase — read another node's files
other_node=$(( (NODE_ID % TOTAL_NODES) + 1 ))
log_info "Node ${NODE_ID}: cross-reading node ${other_node} data..."
xread_start=$(date +%s%N)

for i in $(seq 1 $FILE_COUNT); do
    dd if="$TESTDIR/node${other_node}/data_${i}" of=/dev/null bs=1M 2>/dev/null || {
        test_fail "Cross-read failed: node ${other_node} file ${i}"
    }
done

xread_end=$(date +%s%N)
xread_ms=$(( (xread_end - xread_start) / 1000000 ))
xread_mbps=$(awk "BEGIN {printf \"%.1f\", ${TOTAL_MB} / (${xread_ms} / 1000.0)}")
log_info "Node ${NODE_ID}: cross-read throughput: ${xread_mbps} MB/s"

# Verify file sizes
for i in $(seq 1 $FILE_COUNT); do
    sz=$(stat -c%s "$TESTDIR/node${NODE_ID}/data_${i}")
    expected=$((FILE_SIZE_MB * 1048576))
    assert_equals "$expected" "$sz" "File data_${i} size correct"
done

# Barrier: all done
barrier_signal "tp_done"
barrier_wait "tp_done" "$TOTAL_NODES"

# Node 1: aggregate report
if [ "$NODE_ID" = "1" ]; then
    log_info "=== Throughput Summary ==="
    for n in $(seq 1 "$TOTAL_NODES"); do
        w=$(cat "$TESTDIR/node${n}/write_mbps" 2>/dev/null || echo "N/A")
        r=$(cat "$TESTDIR/node${n}/read_mbps" 2>/dev/null || echo "N/A")
        log_info "  Node ${n}: write=${w} MB/s  read=${r} MB/s"
    done
fi

test_end
