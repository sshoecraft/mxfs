#!/bin/bash
# drc_phase_harvest.sh — harvest mxfs-DRCph phase marks (+ DCSTK/DROPCACHES)
# from every node's dmesg with WALL-CLOCK timestamps, one file per node, into
# an output directory.  Used to attribute dir_reuse_coherency barrier waits
# (D-503 residual): the last create-done per round is the wrbar straggler.
# Usage: drc_phase_harvest.sh <out_dir> [nnodes]
set -u
OUT="${1:?out dir}"; N="${2:-32}"
mkdir -p "$OUT"
TOOLS="$(cd "$(dirname "$0")/../tools" && pwd)"
for i in $(seq 1 "$N"); do
    (
        "$TOOLS/mxfs_sshpass.sh" "test$i" \
            'dmesg --time-format=iso 2>/dev/null | grep -a "mxfs-DRCph\|DROPCACHES-HUNG"' \
            2>/dev/null | grep -a '^20' > "$OUT/drcph_test$i.txt"
    ) &
done
wait
wc -l "$OUT"/drcph_test*.txt | tail -1
