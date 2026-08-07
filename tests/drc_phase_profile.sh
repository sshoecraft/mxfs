#!/bin/bash
# drc_phase_profile.sh <nodes> [dlm]
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess24)
# ----------------------------------------
# `dir_reuse_coherency` completes a fixed 128-file workload in a 100s time box
# and asserts it fits at least DRC_MIN_ROUNDS=8 reuse rounds (RULE 0: slowness
# is a first-class failure).  Rounds completed, derived from the recorded check
# counts (checks = 7*rounds + 2), scale badly with node count for IDENTICAL work:
#
#     nodes    1    2    4    8   16   32
#     rounds  24   21   21   17   13    8      <- caw
#     s/round 3.1  4.8  4.8  5.9  7.7 12.5
#
# At 32 nodes the cluster lands EXACTLY on the floor, so one round of jitter
# flips the criterion to FAIL with all 32 nodes reporting the same failed pace
# check (D-DIR-REUSE-COHERENCY-32-FLAKY -- originally misread as a coherent
# namespace corruption because every node agreed).
#
# The test already stamps per-phase markers to /dev/kmsg:
#     mxfs-DRCph r=<round> rank=<R> PHASE=<create-start|wave1-done|sync1-done
#                                          |wave2-done|create-done|verify-done
#                                          |rm-done>
# This harness harvests them WITH kernel timestamps from every node and turns
# them into a per-phase cost breakdown, so the O(N) term can be attributed to a
# specific phase instead of guessed at.
#
# It does NOT run the criterion (run.sh holds a flock; a criterion that invokes
# run.sh would deadlock -- same reason tests/dd_loss_capture.sh is not a
# criterion).  Run it AFTER a dir_reuse_coherency run: the markers are still in
# each node's ring.
set -u
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
N="${1:-32}"
DLM="${2:-caw}"
OUT=$(mktemp -d)
echo "=== harvesting DRCph markers from $N nodes (out=$OUT) ==="

for i in $(seq 1 "$N"); do
    (
      "$SSH" "test$i" \
        "dmesg | grep -E 'mxfs-DRCph|mxfs-drc-DIRID' | tail -400" \
        > "$OUT/n$i.txt" 2>/dev/null
    ) &
done
wait

python3 - "$OUT" "$N" <<'PY'
import re, sys, os, statistics
out, N = sys.argv[1], int(sys.argv[2])

# kernel ring line: "[  1234.567890] mxfs-DRCph r=3 rank=7 PHASE=wave1-done"
LINE = re.compile(r'\[\s*(\d+\.\d+)\]\s+mxfs-DRCph r=(\d+) rank=(\d+) PHASE=(\S+)')

# per (rank, round) -> {phase: ktime}
ev = {}
for i in range(1, N + 1):
    p = os.path.join(out, f"n{i}.txt")
    if not os.path.exists(p):
        continue
    for ln in open(p, errors='replace'):
        m = LINE.search(ln)
        if not m:
            continue
        t, rnd, rank, ph = float(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
        ev.setdefault((rank, rnd), {})[ph] = t

if not ev:
    print("NO DRCph MARKERS FOUND -- the ring rotated, or the criterion has not run "
          "on this build.  Re-run dir_reuse_coherency and harvest immediately.")
    sys.exit(2)

rounds = sorted({r for (_, r) in ev})
ranks  = sorted({k for (k, _) in ev})
print(f"rounds seen: {rounds[0]}..{rounds[-1]} ({len(rounds)})   ranks: {len(ranks)}")

# Intervals within one node's own round.  All timestamps are that node's own
# CLOCK_MONOTONIC, so intra-node deltas need no cross-node clock alignment.
SEGS = [
    ("wave1  (create half 1)", "create-start", "wave1-done"),
    ("sync1  (log force)",     "wave1-done",   "sync1-done"),
    ("wave2  (create half 2)", "sync1-done",   "wave2-done"),
    ("sync2  (log force)",     "wave2-done",   "create-done"),
    ("verify (dropcaches+ls+lookup+cmp)", "create-done", "verify-done"),
    ("rm     (rank1 rm -rf, others wait)", "verify-done", "rm-done"),
]

print()
print(f"{'phase':38s} {'n':>4s} {'mean':>8s} {'p50':>8s} {'p95':>8s} {'max':>8s}  (seconds)")
tot_mean = 0.0
for label, a, b in SEGS:
    vals = []
    for (rank, rnd), d in ev.items():
        if a in d and b in d and d[b] >= d[a]:
            vals.append(d[b] - d[a])
    if not vals:
        print(f"{label:38s} {0:4d}   (no samples)")
        continue
    vals.sort()
    mean = statistics.fmean(vals)
    p50 = vals[len(vals)//2]
    p95 = vals[min(len(vals)-1, int(len(vals)*0.95))]
    tot_mean += mean
    print(f"{label:38s} {len(vals):4d} {mean:8.3f} {p50:8.3f} {p95:8.3f} {max(vals):8.3f}")
print(f"{'SUM of phase means':38s} {'':4s} {tot_mean:8.3f}")

# Full round wall, per node: create-start(r) -> create-start(r+1)
walls = []
for rank in ranks:
    for r in rounds:
        a = ev.get((rank, r), {}).get('create-start')
        b = ev.get((rank, r+1), {}).get('create-start')
        if a is not None and b is not None and b > a:
            walls.append(b - a)
if walls:
    walls.sort()
    print(f"\nfull round wall (create-start -> next create-start): "
          f"n={len(walls)} mean={statistics.fmean(walls):.3f}s "
          f"p50={walls[len(walls)//2]:.3f}s max={max(walls):.3f}s")
    print(f"  -> unaccounted (barriers + mkdir + time-box coord): "
          f"{statistics.fmean(walls) - tot_mean:.3f}s/round")

# Per-round breakdown so a single pathological round is visible rather than
# averaged away.
print(f"\n{'round':>5s} {'wave1':>7s} {'sync1':>7s} {'wave2':>7s} {'sync2':>7s} {'verify':>7s} {'rm':>7s}   (mean over ranks)")
for r in rounds:
    row = [f"{r:5d}"]
    for _, a, b in SEGS:
        vals = [ev[(k, r)][b] - ev[(k, r)][a]
                for k in ranks
                if (k, r) in ev and a in ev[(k, r)] and b in ev[(k, r)]
                and ev[(k, r)][b] >= ev[(k, r)][a]]
        row.append(f"{statistics.fmean(vals):7.3f}" if vals else f"{'-':>7s}")
    print(" ".join(row))
PY
rc=$?
echo "=== raw per-node captures kept in $OUT ==="
exit $rc
