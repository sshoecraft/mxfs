#!/bin/bash
# drc_straggler_report.sh — per-round, per-node phase-span table for a
# dir_reuse_coherency lap, harvested from every node's kernel ring (the
# script's unconditional mxfs-DRCph markers).  Identifies WHICH node was
# the straggler in each round and WHICH phase ate its time — the wrbar/
# barrier waits on every other node are just this node's tail.
#
# Usage: tests/drc_straggler_report.sh <N> <ring-marker>
#   N            node count (test1..testN)
#   ring-marker  dmesg line that starts the lap window (e.g. MXFS-SESS38-LAP320A)
#
# Output: one line per (round, phase) = slowest node + span, plus a
# per-round total ranking.  Runs the awk remotely so only compact rows
# travel back.
set -u
N="${1:?node count}"
MARK="${2:?ring marker}"
SSH=tools/mxfs_sshpass.sh
TMP=$(mktemp -d)
for i in $(seq 1 "$N"); do
    (
        "$SSH" "test$i" "dmesg | awk '/$MARK/{f=1} f' | grep 'mxfs-DRCph'" 2>/dev/null |
        sed -E 's/^\[ *([0-9]+\.[0-9]+)\].*r=([0-9]+) rank=([0-9]+) PHASE=([a-z0-9-]+).*/\1 \2 \3 \4/' \
        > "$TMP/n$i"
    ) &
done
wait
python3 - "$TMP" "$N" <<'PYEOF'
import sys, os, collections
tmp, n = sys.argv[1], int(sys.argv[2])
# spans[(round, phase)][rank] = duration; phase duration = t - prev_t per node stream
spans = collections.defaultdict(dict)
roundtot = collections.defaultdict(dict)
for i in range(1, n + 1):
    path = os.path.join(tmp, f"n{i}")
    if not os.path.exists(path):
        continue
    prev = None
    rstart = {}
    for ln in open(path):
        p = ln.split()
        if len(p) != 4:
            continue
        t, rnd, rank, ph = float(p[0]), int(p[1]), int(p[2]), p[3]
        if prev is not None:
            spans[(rnd, ph)][rank] = t - prev
        if ph == "create-start":
            rstart[rnd] = t
        if ph == "rm-done" and rnd in rstart:
            roundtot[rnd][rank] = t - rstart[rnd]
        prev = t
print(f"{'rnd':>3} {'phase':>14} {'worst':>7} {'rank':>4} {'p50':>6} {'best':>6}")
for (rnd, ph), d in sorted(spans.items()):
    if not d:
        continue
    vals = sorted(d.values())
    worst_rank = max(d, key=d.get)
    if vals[-1] < 0.5:
        continue  # only phases that matter
    p50 = vals[len(vals) // 2]
    print(f"{rnd:>3} {ph:>14} {vals[-1]:6.2f}s {worst_rank:>4} {p50:5.2f}s {vals[0]:5.2f}s")
print("\nper-round wall (create-start..rm-done), worst node:")
for rnd, d in sorted(roundtot.items()):
    if not d:
        continue
    worst_rank = max(d, key=d.get)
    print(f"  r={rnd} worst={d[worst_rank]:.1f}s rank={worst_rank}  median={sorted(d.values())[len(d)//2]:.1f}s")
PYEOF
rm -rf "$TMP"
