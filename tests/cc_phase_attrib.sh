#!/bin/bash
# cc_phase_attrib.sh — per-node phase attribution for crash_consistency.
#
# crash_consistency emits `mxfs-CCph rank=$R PHASE=<p>` to /dev/kmsg at each
# phase boundary (tests/suite/crash_consistency.sh).  When the criterion blows
# its RULE-0 budget the harness records only NO_TERMINAL_RECORD=N, which says
# nothing about WHERE the nodes were.  This tool answers that: it harvests the
# markers of the MOST RECENT run from every node and prints
#   - per-node wall of each phase interval,
#   - which terminal phase each node reached (finishers vs stragglers),
#   - min/median/max per phase across the cluster.
#
# Why the final barrier makes every node look stuck: after PHASE=count-done the
# script blocks in `coord_barrier cc_done`.  One straggler therefore prevents
# EVERY node from reaching coord_done, so all N report NO_TERMINAL_RECORD even
# though many finished their own work.  The phase table separates the two.
#
# usage: cc_phase_attrib.sh [N]        (default 32)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
cd "$REPO"
N="${1:-32}"

OUT=$(mktemp -d)
for i in $(seq 1 "$N"); do
    ( tools/mxfs_sshpass.sh "test$i" \
        "dmesg -T | grep -a 'mxfs-CCph rank=$i PHASE=' | tail -40" \
        2>/dev/null > "$OUT/n$i" ) &
done
wait

N="$N" OUT="$OUT" python3 - <<'PYEOF'
import os, re, datetime, statistics

N   = int(os.environ["N"])
OUT = os.environ["OUT"]

# crash_consistency's phase chain, in execution order.
CHAIN = ["start", "barrier-ready-done", "datawrite-done", "md5write-done",
         "barrier-written-done", "dropcaches-done", "verify-done",
         "count-done", "barrier-done-done"]
# Interval label -> (from, to).  Names describe the WORK done in the interval.
INTERVALS = [
    ("wait-ready",  "start",                "barrier-ready-done"),
    ("datawrite",   "barrier-ready-done",   "datawrite-done"),
    ("md5write",    "datawrite-done",       "md5write-done"),
    ("wait-written","md5write-done",        "barrier-written-done"),
    ("dropcaches",  "barrier-written-done", "dropcaches-done"),
    ("verify",      "dropcaches-done",      "verify-done"),
    ("count",       "verify-done",          "count-done"),
]
LINE = re.compile(r"^\[(.+?)\]\s+mxfs-CCph rank=(\d+) PHASE=(\S+)")

def parse(ts):
    # dmesg -T format: "Tue Aug  4 04:40:28 2026"
    return datetime.datetime.strptime(ts.strip(), "%a %b %d %H:%M:%S %Y")

nodes = {}
for i in range(1, N + 1):
    p = os.path.join(OUT, "n%d" % i)
    try:
        raw = open(p, errors="replace").read().splitlines()
    except OSError:
        continue
    ev = []
    for ln in raw:
        m = LINE.match(ln.strip())
        if m:
            ev.append((parse(m.group(1)), m.group(3)))
    if not ev:
        continue
    # Most recent run = from the LAST PHASE=start onward.
    last = max((k for k, (_, ph) in enumerate(ev) if ph == "start"), default=None)
    if last is None:
        continue
    run = ev[last:]
    # First occurrence of each phase within this run.
    seen = {}
    for t, ph in run:
        seen.setdefault(ph, t)
    nodes[i] = seen

if not nodes:
    print("no CCph markers found on any node")
    raise SystemExit(1)

# Terminal phase reached, per node.
def terminal(seen):
    best = None
    for ph in CHAIN:
        if ph in seen:
            best = ph
    return best

print("=== crash_consistency per-node phase attribution (n=%d nodes reporting) ===" % len(nodes))
hdr = "node  " + "".join("%12s" % lbl for lbl, _, _ in INTERVALS) + "   terminal"
print(hdr)
print("-" * len(hdr))
cols = {lbl: [] for lbl, _, _ in INTERVALS}
starts = []
for i in sorted(nodes):
    seen = nodes[i]
    if "start" in seen:
        starts.append(seen["start"])
    row = "%-6d" % i
    for lbl, a, b in INTERVALS:
        if a in seen and b in seen:
            d = (seen[b] - seen[a]).total_seconds()
            cols[lbl].append(d)
            row += "%12.0f" % d
        else:
            row += "%12s" % "-"
    print(row + "   " + str(terminal(seen)))

print()
print("=== per-phase distribution across cluster (seconds) ===")
print("%-14s %6s %6s %6s %6s %6s" % ("phase", "n", "min", "med", "max", "sum-of-max"))
crit = 0.0
for lbl, _, _ in INTERVALS:
    v = cols[lbl]
    if not v:
        print("%-14s %6d %6s %6s %6s" % (lbl, 0, "-", "-", "-"))
        continue
    crit += max(v)
    print("%-14s %6d %6.0f %6.0f %6.0f %6.0f"
          % (lbl, len(v), min(v), statistics.median(v), max(v), crit))

# Terminal-phase census: finishers vs stragglers.
census = {}
for i in nodes:
    census.setdefault(terminal(nodes[i]), []).append(i)
print()
print("=== terminal phase census ===")
for ph in CHAIN:
    if ph in census:
        ids = sorted(census[ph])
        print("%-22s %2d node(s): %s" % (ph, len(ids), ",".join(map(str, ids))))

if starts:
    span = (max(starts) - min(starts)).total_seconds()
    print()
    print("run start skew across nodes: %.0fs   (first %s)" % (span, min(starts)))
PYEOF
