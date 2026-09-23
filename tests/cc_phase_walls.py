# sess435: per-rank crash_consistency phase walls from a retained run archive (/tmp/run_crash_consistency_<id>/kernlog_test*). usage: python3 tests/cc_phase_walls.py [archive_dir]
import re, sys, glob, statistics, os

DIR = sys.argv[1] if len(sys.argv) > 1 else "/tmp/run_crash_consistency_20260828T202007Z"
PHASES = ["start","barrier-ready-done","datawrite-done","md5write-done",
          "barrier-written-done","dropcaches-done","verify-done","count-done",
          "barrier-done-done"]

TS_RE = re.compile(r'^\[(\w+ \w+ \d+ \d+:\d+:\d+ \d+)\]')
CCPH_RE = re.compile(r'mxfs-CCph rank=(\d+) PHASE=(\S+)')

import datetime
def parse_ts(s):
    # e.g. Fri Aug 28 20:26:30 2026
    return datetime.datetime.strptime(s, "%a %b %d %H:%M:%S %Y")

PATTERNS = ['P12-AGBAST','BAST','P-DIRWR','dir.*EX','stuck for','P130','P131',
            'ILOCK','grant','retry','Corruption','mxfs-cc-FAIL']
PAT_RE = [(p, re.compile(p)) for p in PATTERNS]
MXFS_RE = re.compile(r'mxfs:')

results = {}  # rank -> dict phase->(line_no, ts)
window_counts = {}  # rank -> dict pattern-> count
mxfs_total = {}  # rank -> count of 'mxfs:' lines in window
last_marker_line = {}
last_start_line = {}
node_files = {}

for n in range(1,33):
    fn = os.path.join(DIR, f"kernlog_test{n}")
    node_files[n] = fn
    lines = None
    with open(fn, 'r', errors='replace') as f:
        lines = f.readlines()
    # find last PHASE=start line index
    last_start_idx = None
    for i, line in enumerate(lines):
        if 'mxfs-CCph' in line:
            m = CCPH_RE.search(line)
            if m and m.group(2) == 'start':
                last_start_idx = i
    if last_start_idx is None:
        results[n] = {}
        window_counts[n] = {p:0 for p,_ in PAT_RE}
        mxfs_total[n] = 0
        last_marker_line[n] = None
        last_start_line[n] = None
        continue
    last_start_line[n] = last_start_idx+1
    # collect phase markers from last_start_idx to end, in order, only first occurrence of each phase after start
    phase_ts = {}
    last_idx_seen = last_start_idx
    for i in range(last_start_idx, len(lines)):
        line = lines[i]
        if 'mxfs-CCph' in line:
            m = CCPH_RE.search(line)
            if m:
                rank = int(m.group(1))
                phase = m.group(2)
                if phase in PHASES and phase not in phase_ts:
                    tsm = TS_RE.match(line)
                    ts = parse_ts(tsm.group(1)) if tsm else None
                    phase_ts[phase] = (i+1, ts)
                    last_idx_seen = i
    results[n] = phase_ts
    last_marker_line[n] = last_idx_seen+1

    # window = last_start_idx .. last_idx_seen (inclusive), count patterns
    window_lines = lines[last_start_idx:last_idx_seen+1]
    counts = {p:0 for p,_ in PAT_RE}
    mcount = 0
    for line in window_lines:
        for p, rgx in PAT_RE:
            if rgx.search(line):
                counts[p]+=1
        if MXFS_RE.search(line):
            mcount += 1
    window_counts[n] = counts
    mxfs_total[n] = mcount

# ---- Part 1: per-rank deltas table ----
print("="*100)
print("PART 1: per-rank phase deltas (seconds); missing markers noted")
print("="*100)
pair_defs = [
    ("ready-wait", "start", "barrier-ready-done"),
    ("datawrite", "barrier-ready-done", "datawrite-done"),
    ("md5write", "datawrite-done", "md5write-done"),
    ("written-wait", "md5write-done", "barrier-written-done"),
    ("dropcaches", "barrier-written-done", "dropcaches-done"),
    ("verify", "dropcaches-done", "verify-done"),
    ("count", "verify-done", "count-done"),
    ("done-wait", "count-done", "barrier-done-done"),
]

header = "rank | " + " | ".join(p[0] for p in pair_defs) + " | missing"
print(header)
per_phase_deltas = {p[0]: [] for p in pair_defs}
for n in range(1,33):
    phase_ts = results[n]
    row = []
    missing = [ph for ph in PHASES if ph not in phase_ts]
    for label, a, b in pair_defs:
        if a in phase_ts and b in phase_ts:
            ta = phase_ts[a][1]; tb = phase_ts[b][1]
            if ta is not None and tb is not None:
                d = (tb-ta).total_seconds()
                row.append(f"{d:.0f}")
                per_phase_deltas[label].append(d)
            else:
                row.append("NA")
        else:
            row.append("NA")
    print(f"{n:4d} | " + " | ".join(f"{r:>6}" for r in row) + " | " + (",".join(missing) if missing else "none"))

print()
print("="*100)
print("PART 2: summary per phase-pair: min/median/max across ranks (only ranks with both markers)")
print("="*100)
for label,_,_ in pair_defs:
    vals = per_phase_deltas[label]
    if vals:
        print(f"{label:15s} n={len(vals):2d} min={min(vals):.0f} median={statistics.median(vals):.0f} max={max(vals):.0f}")
    else:
        print(f"{label:15s} n=0 (no ranks had both markers)")

print()
print("="*100)
print("PART 3: pattern counts in window [last PHASE=start .. last marker] per node")
print("="*100)
fleet_totals = {p:0 for p,_ in PAT_RE}
per_node_pat = {p: [] for p,_ in PAT_RE}
for n in range(1,33):
    for p,_ in PAT_RE:
        c = window_counts[n][p]
        fleet_totals[p] += c
        per_node_pat[p].append((n,c))

for p,_ in PAT_RE:
    top3 = sorted(per_node_pat[p], key=lambda x:-x[1])[:3]
    top3s = ", ".join(f"test{n}={c}" for n,c in top3)
    print(f"{p:15s} fleet_total={fleet_totals[p]:6d}  top3: {top3s}")

print()
mxfs_sorted = sorted(mxfs_total.items(), key=lambda x:-x[1])
mxfs_grand_total = sum(mxfs_total.values())
print(f"'mxfs:' grep -c total across window, fleet sum = {mxfs_grand_total}")
print("top5 nodes by 'mxfs:' count in window:")
for n,c in mxfs_sorted[:5]:
    print(f"  test{n}: {c}")

print()
print("Nodes with no PHASE=start found at all:", [n for n in range(1,33) if last_start_line[n] is None])

# save results dict for part4 use
import pickle
with open('/tmp/claude-1000/-src-mxfs/15472ae1-4ec0-4df1-8a88-9eb5ee167561/scratchpad/cc_results.pkl','wb') as f:
    pickle.dump({'last_start_line':last_start_line,'results':results,'last_marker_line':last_marker_line}, f)
