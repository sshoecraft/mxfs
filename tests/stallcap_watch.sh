#!/bin/bash
# stallcap_watch.sh — per-node stall forensics for the 32/caw spurious-shutdown
# family (ccloop c7ee71c6 sess12-D).  Polls dmesg for the AG-AIL-STALL /
# NOINO-LISTDRAIN prints; on first hit, snapshots every candidate holder's
# kernel stack so the >150s folio/ILOCK holder that hung_task never dumps
# (interruptible CAW-poll sleeps) is captured live.
#
# Runs ON a node.  Usage: stallcap_watch.sh [timeout_s] [outdir]
# Triggers: "AG-AIL-STALL" | "P-NOINO-LISTDRAIN" | "NOINO-DRAIN-RETRY"
# Captures (×3 rounds, 2s apart, into $OUT/):
#   - dmesg tail
#   - every task whose /proc/PID/stack mentions mxfs_/xfs_/folio/iomap
#   - all D-state tasks' stacks
#   - /proc/meminfo writeback counters
# Exits after capture (or timeout with no trigger).

T="${1:-120}"
OUT="${2:-/root/stallcap}"
PAT='AG-AIL-STALL|P-NOINO-LISTDRAIN|NOINO-DRAIN-RETRY'

mkdir -p "$OUT"
start=$(date +%s)
mark=$(dmesg | grep -cE "$PAT")

while :; do
    now=$(date +%s)
    [ $((now - start)) -ge "$T" ] && { echo "stallcap: no trigger in ${T}s"; exit 1; }
    cur=$(dmesg | grep -cE "$PAT")
    [ "$cur" -gt "$mark" ] && break
    sleep 0.5
done

echo "stallcap: TRIGGERED at $(date -u +%H:%M:%S) (uptime $(cut -d. -f1 /proc/uptime)s)"
for round in 1 2 3; do
    d="$OUT/round$round"
    mkdir -p "$d"
    dmesg | tail -n 300 > "$d/dmesg.txt"
    grep -E 'Dirty|Writeback' /proc/meminfo > "$d/meminfo.txt"
    # Snapshot stacks: mxfs/xfs/iomap/folio-involved tasks + all D-state.
    for p in /proc/[0-9]*; do
        pid=${p#/proc/}
        st=$(cat "$p/stack" 2>/dev/null) || continue
        [ -n "$st" ] || continue
        stat=$(awk '{print $3}' "$p/stat" 2>/dev/null)
        comm=$(cat "$p/comm" 2>/dev/null)
        if echo "$st" | grep -qE 'mxfs_|xfs_|iomap_|folio_|write_cache_pages' \
           || [ "$stat" = "D" ]; then
            {
                echo "=== pid=$pid comm=$comm state=$stat"
                echo "$st"
                echo
            } >> "$d/stacks.txt"
        fi
    done
    sleep 2
done
echo "stallcap: captured 3 rounds in $OUT"
