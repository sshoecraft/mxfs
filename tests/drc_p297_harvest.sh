#!/bin/bash
# drc_p297_harvest.sh — harvest P297-TKT / P298 / exwin probe lines from every
# node's dmesg with wall-clock timestamps, one file per node.  Companion to
# drc_phase_harvest.sh for D-503 residual pace analysis.
# Usage: drc_p297_harvest.sh <out_dir> [nnodes] [pattern]
set -u
OUT="${1:?out dir}"; N="${2:-32}"; PAT="${3:-P297-TKT}"
mkdir -p "$OUT"
TOOLS="$(cd "$(dirname "$0")/../tools" && pwd)"
for i in $(seq 1 "$N"); do
    (
        "$TOOLS/mxfs_sshpass.sh" "test$i" \
            "dmesg --time-format=iso 2>/dev/null | grep -a '$PAT'" \
            2>/dev/null | grep -a '^20' > "$OUT/p297_test$i.txt"
    ) &
done
wait
wc -l "$OUT"/p297_test*.txt | tail -1
