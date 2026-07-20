#!/bin/bash
# MXFS Performance Benchmark
# Tests: sequential write, sequential read, metadata ops
# Usage: mxfs_bench.sh <mountpoint> <label>

MP=${1:-/mnt/shared}
LABEL=${2:-test}
TESTFILE="$MP/.bench_$$"
RESULTS="/tmp/bench_${LABEL}_$(hostname).txt"

echo "=== Benchmark: $LABEL on $(hostname) ===" | tee $RESULTS
echo "Mount: $(mount | grep "$MP")" | tee -a $RESULTS
echo "" | tee -a $RESULTS

# Sequential write (16MB — smaller to keep it fast)
echo "--- Sequential Write (16MB) ---" | tee -a $RESULTS
sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
TIME=$(dd if=/dev/zero of=$TESTFILE bs=1M count=16 conv=fdatasync 2>&1)
RATE=$(echo "$TIME" | grep -oP '[\d.]+ [MG]B/s' || echo "$TIME" | tail -1)
echo "  Write: $RATE" | tee -a $RESULTS

# Sequential read
echo "--- Sequential Read (16MB) ---" | tee -a $RESULTS
sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
TIME=$(dd if=$TESTFILE of=/dev/null bs=1M 2>&1)
RATE=$(echo "$TIME" | grep -oP '[\d.]+ [MG]B/s' || echo "$TIME" | tail -1)
echo "  Read: $RATE" | tee -a $RESULTS

rm -f $TESTFILE

# Small file create (50 files)
echo "--- Metadata: Create 50 files ---" | tee -a $RESULTS
METADIR="$MP/.benchmeta_$$"
mkdir -p $METADIR
sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
START=$(date +%s%N)
for i in $(seq 1 50); do
    echo "x" > "$METADIR/file_$i"
done
sync
END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000 ))
echo "  Create 50 files: ${ELAPSED}ms" | tee -a $RESULTS

# Stat 50 files
echo "--- Metadata: Stat 50 files ---" | tee -a $RESULTS
sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
START=$(date +%s%N)
for i in $(seq 1 50); do
    stat "$METADIR/file_$i" > /dev/null 2>&1
done
END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000 ))
echo "  Stat 50 files: ${ELAPSED}ms" | tee -a $RESULTS

# Delete 50 files
echo "--- Metadata: Delete 50 files ---" | tee -a $RESULTS
START=$(date +%s%N)
rm -rf $METADIR
sync
END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000 ))
echo "  Delete 50 files: ${ELAPSED}ms" | tee -a $RESULTS

echo "" | tee -a $RESULTS
echo "=== Benchmark complete ===" | tee -a $RESULTS
