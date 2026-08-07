#!/bin/bash
# drc_lap_probe.sh — snapshot per-node mxfs log/AIL/memory/sched state, tagged.
# Usage: tests/drc_lap_probe.sh <tag> [outdir]
# Captures, per node: /proc/fs/mxfs/stat, /sys/fs/mxfs/*/log/*, meminfo
# (Dirty/Writeback/Slab), PSI (cpu/io/mem some), /proc/stat steal, uptime.
# One ssh round per node, all nodes in parallel. Written for the sess39
# dir_reuse run-over-run degradation RULE-4 loop: diff consecutive tags to
# see which backlog grows across runs and drains across idle.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${1:?usage: drc_lap_probe.sh <tag> [outdir]}"
OUT="${2:-$REPO/tests/logs/sess39_lap}"
mkdir -p "$OUT"
N="${MXFS_N:-32}"
for i in $(seq 1 "$N"); do
    (
        "$REPO/tools/mxfs_sshpass.sh" "test$i" "
            echo '== mxfs_stat =='; cat /proc/fs/mxfs/stat 2>/dev/null
            echo '== log =='; for f in /sys/fs/mxfs/*/log/*; do echo \"\$f \$(cat \$f 2>/dev/null)\"; done
            echo '== mem =='; grep -E 'Dirty|Writeback:|^Slab|SReclaimable|SUnreclaim|MemFree' /proc/meminfo
            echo '== psi =='; for p in cpu io memory; do echo \"\$p \$(head -1 /proc/pressure/\$p 2>/dev/null)\"; done
            echo '== cpu =='; grep '^cpu ' /proc/stat
            echo '== up =='; cat /proc/uptime
        " 2>/dev/null > "$OUT/${TAG}_n${i}.txt"
    ) &
done
wait
echo "$(date +%s) $TAG" >> "$OUT/tags.txt"
echo "snapshot $TAG done -> $OUT"
