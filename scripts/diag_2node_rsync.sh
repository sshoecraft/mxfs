#!/bin/bash
# diag_2node_rsync.sh — RULE 4 instrumentation for the scaling_curve /
# rsync perf pathology (sess19): solo rsync on a 2-node cluster (peer
# idle) runs ~127 s vs ~5 s truly-single-node.  Locks are cached until
# BAST and an idle peer sends no BASTs, so some per-op path is forcing
# disk coordination anyway.  This measures WHERE:
#   - /proc/diskstats delta on the shared LUN (both nodes) over the run
#   - dmesg mxfs tag counts (which instrumented paths fire per-file)
#   - rsync kernel stack samples every 2 s (the actual wait site)
#
# Usage: scripts/diag_2node_rsync.sh [--cap SECONDS]   (default cap 300)
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${MXFS_SSH_TIMEOUT:=600}"
source "$SCRIPT_DIR/../tests/criteria/lib.sh"
stamp() { echo "[$(date +%H:%M:%S)] $*"; }

CAP=300
[ "${1:-}" = "--cap" ] && CAP="$2"

N1=test1; N2=test2
SRC=/root/open-gpu-kernel-modules
OUT=/tmp/diag2n.$$
mkdir -p "$OUT"

stamp "=== teardown + fresh 2-node cluster ==="
teardown_all "$N1 $N2"
fresh_cluster_mount "$N1" "$N2" || { echo "MOUNT FAIL"; exit 1; }

for h in "$N1" "$N2"; do
    ssh_node "$h" "dmesg -C; grep ' sda ' /proc/diskstats" > "$OUT/$h.disk0"
done

stamp "=== solo rsync on $N1 (peer idle), cap ${CAP}s ==="
(
    ssh_node "$N1" "
        mkdir -p $MXFS_MOUNT/diag/a1
        t0=\$(date +%s%N)
        timeout $CAP rsync -a --no-i-r $SRC/ $MXFS_MOUNT/diag/a1/ >/dev/null 2>&1
        rc=\$?
        sync
        t1=\$(date +%s%N)
        echo SOLO_MS=\$(( (t1 - t0) / 1000000 )) rc=\$rc" | tail -1 > "$OUT/solo.ms"
) &
runner=$!

# Stack sampler — runs until the rsync reports in.
while kill -0 $runner 2>/dev/null; do
    ssh_node "$N1" 'p=$(pgrep -x rsync | tail -1); [ -n "$p" ] && { echo "stat=$(awk "{print \$3}" /proc/$p/stat 2>/dev/null)"; cat /proc/$p/stack 2>/dev/null; echo ===; }' >> "$OUT/stacks" 2>/dev/null
    sleep 2
done
wait $runner 2>/dev/null

for h in "$N1" "$N2"; do
    ssh_node "$h" "grep ' sda ' /proc/diskstats" > "$OUT/$h.disk1"
    ssh_node "$h" 'dmesg | grep -oE "mxfs: [A-Z0-9_-]+" | sort | uniq -c | sort -rn | head -15' > "$OUT/$h.tags"
done

echo
cat "$OUT/solo.ms"
echo
echo "=== diskstats delta (reads/readsect/writes/writesect) ==="
for h in "$N1" "$N2"; do
    paste "$OUT/$h.disk0" "$OUT/$h.disk1" | awk -v h="$h" \
      '{printf "%s: reads=%d rd_sect=%d writes=%d wr_sect=%d flush=%d\n", h, $18-$4, $20-$6, $22-$8, $24-$10, $32-$16}'
done
echo
echo "=== dmesg tag counts during run ==="
for h in "$N1" "$N2"; do echo "--- $h ---"; cat "$OUT/$h.tags"; done
echo
echo "=== top stack frames across samples ==="
grep -E '^\[' "$OUT/stacks" | sed 's/+.*//; s/^\[<0>\] //' | sort | uniq -c | sort -rn | head -15
echo
echo "raw data: $OUT"
