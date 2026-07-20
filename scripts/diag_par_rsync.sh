#!/bin/bash
# diag_par_rsync.sh — RULE 4 instrumentation for the scaling_curve
# multi-node penalty (sess23 of run 14d31183): warm 1-node rsync wall
# ~3.4 s but ANY >=2-node parallel rsync (each node its own subdir)
# flattens at ~6-7 s per node (ratio >150% = gate FAIL).  The penalty
# is a near-constant ~3 s once peers are active, not super-linear.
#
# Measures, for a parallel N-node rsync (default 2):
#   - per-node wall (same workload as tests/criteria/scaling_curve.sh)
#   - /proc/diskstats delta on the shared LUN per node
#   - rsync kernel stack samples every 1 s on every node (wait site)
#   - dmesg mxfs tag counts + DLM cache-stat lines per node
#
# Usage: scripts/diag_par_rsync.sh [NODES...]   (default: test1 test2)
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${MXFS_SSH_TIMEOUT:=600}"
source "$SCRIPT_DIR/../tests/criteria/lib.sh"
stamp() { echo "[$(date +%H:%M:%S)] $*"; }

NODES=("$@")
[ "${#NODES[@]}" -ge 1 ] || NODES=(test1 test2)
SRC=/root/open-gpu-kernel-modules
OUT=/tmp/diagpar.$$
mkdir -p "$OUT"

stamp "=== teardown + fresh ${#NODES[@]}-node cluster ==="
teardown_all "${NODES[*]}"
fresh_cluster_mount "${NODES[@]}" || { echo "MOUNT FAIL"; exit 1; }

for h in "${NODES[@]}"; do
    ssh_node "$h" "dmesg -C; grep ' sda ' /proc/diskstats" > "$OUT/$h.disk0"
done
ssh_node "${NODES[0]}" "rm -rf $MXFS_MOUNT/scale; mkdir -p $MXFS_MOUNT/scale; touch $MXFS_MOUNT/scale/.go; sync"

stamp "=== parallel rsync on ${NODES[*]} ==="
# Host-side view of the shared LUN's backing NVMe across the rsync
# window: aggregate sectors + io_ticks tell device-saturation from
# FS-coordination apart (sess29).
grep " nvme0n1 " /proc/diskstats > "$OUT/host.disk0"
pids=()
for i in "${!NODES[@]}"; do
    h="${NODES[$i]}"
    id=$((i + 1))
    (
        ssh_node "$h" "
            for try in \$(seq 1 60); do [ -e $MXFS_MOUNT/scale/.go ] && break; sleep 0.5; done
            mkdir -p $MXFS_MOUNT/scale/n${id}
            t0=\$(date +%s%N)
            rsync -a --no-i-r --max-size=64k $SRC/ $MXFS_MOUNT/scale/n${id}/ >/dev/null 2>&1
            tr=\$(date +%s%N)
            sync
            t1=\$(date +%s%N)
            echo WALL_MS=\$(( (t1 - t0) / 1000000 )) RSYNC_MS=\$(( (tr - t0) / 1000000 )) SYNC_MS=\$(( (t1 - tr) / 1000000 ))
        " | tail -1 > "$OUT/$h.ms"
    ) & pids+=($!)
done

# Stack sampler on every node until all runners finish.
(
    while :; do
        alive=0
        for p in "${pids[@]}"; do kill -0 "$p" 2>/dev/null && alive=1; done
        [ "$alive" = "0" ] && break
        for h in "${NODES[@]}"; do
            ssh_node "$h" 'for p in $(pgrep -x rsync); do s=$(awk "{print \$3}" /proc/$p/stat 2>/dev/null); st=$(cat /proc/$p/stack 2>/dev/null | head -6 | tr "\n" "|"); echo "$s $st"; done' \
                | sed "s/^/$h /" >> "$OUT/stacks" 2>/dev/null
        done
        sleep 1
    done
) &
sampler=$!
for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
wait "$sampler" 2>/dev/null
grep " nvme0n1 " /proc/diskstats > "$OUT/host.disk1"
paste "$OUT/host.disk0" "$OUT/host.disk1" | awk \
  '{printf "HOST nvme0n1: reads=%d rd_mb=%.0f writes=%d wr_mb=%.0f io_ticks_ms=%d flush=%d\n", \
    $24-$4, ($26-$6)/2048, $28-$8, ($30-$10)/2048, $33-$13, $39-$19}'

for h in "${NODES[@]}"; do
    ssh_node "$h" "grep ' sda ' /proc/diskstats" > "$OUT/$h.disk1"
    ssh_node "$h" 'dmesg | grep -oE "mxfs: [A-Z0-9_-]+" | sort | uniq -c | sort -rn | head -12' > "$OUT/$h.tags"
    ssh_node "$h" 'dmesg | grep "DLM cache" | tail -2' > "$OUT/$h.dlmstats"
done

echo
echo "=== per-node wall ==="
for h in "${NODES[@]}"; do echo "$h: $(cat "$OUT/$h.ms")"; done
echo
echo "=== diskstats delta (reads/rd_sect/writes/wr_sect/flush) ==="
for h in "${NODES[@]}"; do
    paste "$OUT/$h.disk0" "$OUT/$h.disk1" | awk -v h="$h" \
      '{printf "%s: reads=%d rd_sect=%d writes=%d wr_sect=%d flush=%d\n", h, $18-$4, $20-$6, $22-$8, $24-$10, $32-$16}'
done
echo
echo "=== dmesg tag counts during run ==="
for h in "${NODES[@]}"; do echo "--- $h ---"; cat "$OUT/$h.tags"; cat "$OUT/$h.dlmstats"; done
echo
echo "=== top rsync stack signatures across samples (state + frames) ==="
sort "$OUT/stacks" 2>/dev/null | uniq -c | sort -rn | head -20
echo
echo "raw data: $OUT"
