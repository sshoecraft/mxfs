#!/bin/bash
# host_write_sampler.sh — 1Hz clyde-side write-path sampler (sess39).
# Captures: nvme0n1 write ops/time (diskstats), a 4K O_DSYNC fsync-latency
# probe on the root fs (jbd2 commit cost proxy), and per-process cumulative
# write_bytes for the big writers (worldserver, python3, journald, qemu sum).
# Output: one line per second to $1 (default scratchpad hostsamp.txt).
# Usage: tests/host_write_sampler.sh <outfile> <iterations>
set -u
OUT="${1:?usage: host_write_sampler.sh <outfile> <iters>}"
ITERS="${2:-3600}"
PROBE="$(dirname "$OUT")/.fsyncprobe"
WS=$(pgrep -x worldserver | head -1 || true)
PY=$(pgrep -x python3 | head -1 || true)
JD=$(pgrep -x systemd-journal | head -1 || true)
for _ in $(seq 1 "$ITERS"); do
    t=$(date +%s.%N)
    nv=$(awk '$3=="nvme0n1"{print $8, $11}' /proc/diskstats)
    t1=$(date +%s.%N)
    dd if=/dev/zero of="$PROBE" bs=4096 count=1 oflag=dsync conv=notrunc 2>/dev/null
    t2=$(date +%s.%N)
    wws=$(awk '/^write_bytes/{print $2}' "/proc/$WS/io" 2>/dev/null || echo 0)
    wpy=$(awk '/^write_bytes/{print $2}' "/proc/$PY/io" 2>/dev/null || echo 0)
    wjd=$(awk '/^write_bytes/{print $2}' "/proc/$JD/io" 2>/dev/null || echo 0)
    echo "$t $nv fs=$(awk "BEGIN{print $t2-$t1}") ws=$wws py=$wpy jd=$wjd" >> "$OUT"
    sleep 1
done
