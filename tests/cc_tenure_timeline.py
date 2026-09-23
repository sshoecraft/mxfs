#!/usr/bin/env python3
"""
cc_tenure_timeline.py <dir-of-per-node-.log-files>

Parses per-node kernel journal excerpts (files named testN.log, grep'd for
'P138-ACQ ', 'P138-BAST', 'mxfs-CCph rank=') and reports:

  1. ino=25165952 P138-ACQ stats: total, per-node counts, elapsed_ms
     distribution, fleet-wide grant-instant (realms field) inter-grant gap
     distribution, and per-node rotation-period distribution.
  2. First 60 fleet-sorted grants: time_ms node elapsed_ms (relative to
     first grant).
  3. P138-BAST: per-node counts + 5 verbatim examples (cut -c1-260).
  4. Per-node mxfs-CCph marker counts, and datawrite/md5write durations
     (journal-timestamp deltas) for test1/8/16/24/32.

Malformed lines (wrong field count, unparsable ino/realms/elapsed_ms) are
counted and skipped, never silently dropped without a report.
"""
import sys, os, re, glob, statistics as st
from datetime import datetime

TARGET_INO = "ino=25165952"

def pctl(sorted_vals, p):
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)

def dist(vals):
    if not vals:
        return {"n": 0}
    s = sorted(vals)
    return {
        "n": len(s),
        "p10": pctl(s, 10), "p50": pctl(s, 50), "p90": pctl(s, 90),
        "p99": pctl(s, 99), "max": s[-1], "min": s[0],
    }

# journal timestamp parsing: "Aug 29 01:02:29" -> seconds-in-window (no year in journalctl -k output)
MONTHS = {m: i+1 for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"])}

def parse_journal_ts(line, year):
    # "Mon DD HH:MM:SS host proc: rest"
    parts = line.split(None, 4)
    if len(parts) < 4:
        return None
    mon, day, hms, host = parts[0], parts[1], parts[2], parts[3]
    if mon not in MONTHS:
        return None
    try:
        dt = datetime(year, MONTHS[mon], int(day), *(int(x) for x in hms.split(":")))
        return dt.timestamp()
    except Exception:
        return None

def main():
    if len(sys.argv) < 2:
        print("usage: cc_tenure_timeline.py <dir>", file=sys.stderr)
        sys.exit(1)
    d = sys.argv[1]
    files = sorted(glob.glob(os.path.join(d, "test*.log")))
    node_re = re.compile(r"(test\d+)\.log$")

    acq_all = []          # all P138-ACQ lines (any ino), for total-line sanity
    acq_target = []        # (node, elapsed_ms, realms, raw_line) for ino=25165952
    bast_per_node = {}      # node -> count
    bast_examples = []      # first 5 verbatim (cut -c1-260)
    ccph_per_node = {}      # node -> {phase: ts_epoch_seconds}
    ccph_count_per_node = {}

    malformed = {"acq": 0, "bast": 0, "ccph": 0}
    total_lines = 0

    YEAR = 2026  # window is 2026-08-29; journalctl -k strips the year

    for fp in files:
        m = node_re.search(fp)
        node = m.group(1) if m else fp
        bast_per_node.setdefault(node, 0)
        ccph_per_node.setdefault(node, {})
        ccph_count_per_node.setdefault(node, 0)
        with open(fp, "r", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                total_lines += 1
                if "P138-ACQ " in line:
                    fields = line.split()
                    fmap = {}
                    for tok in fields:
                        if "=" in tok:
                            k, _, v = tok.partition("=")
                            fmap[k] = v
                    if "ino" not in fmap or "elapsed_ms" not in fmap or "realms" not in fmap:
                        malformed["acq"] += 1
                        continue
                    try:
                        elapsed_ms = int(fmap["elapsed_ms"])
                        realms = int(fmap["realms"])
                    except ValueError:
                        malformed["acq"] += 1
                        continue
                    acq_all.append((node, fmap.get("ino")))
                    if fmap["ino"] == "25165952":
                        acq_target.append((node, elapsed_ms, realms, line))
                elif "P138-BAST" in line:
                    if TARGET_INO in line:
                        bast_per_node[node] = bast_per_node.get(node, 0) + 1
                        if len(bast_examples) < 5:
                            bast_examples.append(line[:260])
                    # count is scoped to ino=25165952 per the task; also track raw malformed check
                    if "ino=" not in line or "realns=" not in line:
                        malformed["bast"] += 1
                elif "mxfs-CCph rank=" in line:
                    mo = re.search(r"PHASE=(\S+)", line)
                    if not mo:
                        malformed["ccph"] += 1
                        continue
                    phase = mo.group(1)
                    ts = parse_journal_ts(line, YEAR)
                    if ts is None:
                        malformed["ccph"] += 1
                        continue
                    ccph_per_node[node][phase] = ts
                    ccph_count_per_node[node] += 1

    print("=== SECTION 1: ino=25165952 P138-ACQ ===")
    print(f"total P138-ACQ lines (any ino) parsed: {len(acq_all)}")
    print(f"total P138-ACQ lines for ino=25165952: {len(acq_target)}")
    print(f"malformed P138-ACQ lines skipped: {malformed['acq']}")
    print()
    print("per-node P138-ACQ ino=25165952 count:")
    per_node_counts = {}
    for node, elapsed_ms, realms, raw in acq_target:
        per_node_counts[node] = per_node_counts.get(node, 0) + 1
    for node in sorted(per_node_counts, key=lambda x: int(x[4:])):
        print(f"  {node}: {per_node_counts[node]}")
    print(f"  (nodes with zero: {sorted(set('test'+str(i) for i in range(1,33)) - set(per_node_counts), key=lambda x: int(x[4:]))})")
    print()

    elapsed_vals = [e for (_, e, _, _) in acq_target]
    ed = dist(elapsed_vals)
    print(f"elapsed_ms distribution over {ed['n']} grants: "
          f"p50={ed.get('p50')} p90={ed.get('p90')} p99={ed.get('p99')} max={ed.get('max')} min={ed.get('min')}")
    print()

    # sort fleet-wide by grant instant g = realms
    fleet_sorted = sorted(acq_target, key=lambda t: t[2])
    gaps = []
    for i in range(len(fleet_sorted) - 1):
        gaps.append(fleet_sorted[i+1][2] - fleet_sorted[i][2])
    gd = dist(gaps)
    print(f"inter-grant gap (g[i+1]-g[i], ms) distribution over {gd['n']} gaps ({len(fleet_sorted)} grants): "
          f"p10={gd.get('p10')} p50={gd.get('p50')} p90={gd.get('p90')} max={gd.get('max')} min={gd.get('min')}")
    print()

    # rotation period per node: g_next_same_node - g_this_same_node
    per_node_grants = {}
    for node, elapsed_ms, realms, raw in fleet_sorted:
        per_node_grants.setdefault(node, []).append(realms)
    print("rotation period per node (ms between successive grants held BY THE SAME NODE):")
    for node in sorted(per_node_grants, key=lambda x: int(x[4:])):
        gl = per_node_grants[node]
        rp = [gl[i+1] - gl[i] for i in range(len(gl)-1)]
        rd = dist(rp)
        print(f"  {node}: grants={len(gl)} rotation_gaps={rd['n']} "
              f"p50={rd.get('p50')} p90={rd.get('p90')} max={rd.get('max')} min={rd.get('min')}")
    print()

    print("=== SECTION 2: first 60 fleet-sorted grants (time_ms node elapsed_ms), rel to first grant ===")
    if fleet_sorted:
        t0 = fleet_sorted[0][2]
        for i, (node, elapsed_ms, realms, raw) in enumerate(fleet_sorted[:60]):
            print(f"  {realms - t0:>8} {node:<8} {elapsed_ms}")
    print()

    print("=== SECTION 3: P138-BAST (ino=25165952) ===")
    total_bast = sum(bast_per_node.values())
    print(f"total P138-BAST ino=25165952 lines: {total_bast}")
    print(f"malformed P138-BAST lines (missing ino=/realns=) skipped from count check: {malformed['bast']}")
    print("per-node counts:")
    for node in sorted(bast_per_node, key=lambda x: int(x[4:])):
        if bast_per_node[node]:
            print(f"  {node}: {bast_per_node[node]}")
    print()
    print("5 verbatim examples (cut -c1-260):")
    for ex in bast_examples:
        print(f"  {ex}")
    print()
    # pairing check: does BAST realns (ns) correspond in time to nearby ACQ realms (ms)?
    print("pairing check: BAST lines carry 'realns=' (nanosecond epoch); ACQ lines carry 'realms=' (millisecond epoch).")
    print("These are DIFFERENT clocks/fields on the same line format family, not identical timestamps;")
    print("checking whether realns/1e6 (ms) falls within [min ACQ realms, max ACQ realms] window for ino=25165952:")
    if acq_target:
        acq_realms_min = min(r for (_, _, r, _) in acq_target)
        acq_realms_max = max(r for (_, _, r, _) in acq_target)
        in_window = 0
        out_window = 0
        for ex in bast_examples:
            mo = re.search(r"realns=(\d+)", ex)
            if mo:
                realns_ms = int(mo.group(1)) / 1e6
                if acq_realms_min <= realns_ms <= acq_realms_max:
                    in_window += 1
                else:
                    out_window += 1
        print(f"  of {len(bast_examples)} example lines: {in_window} fall within ACQ realms window, {out_window} do not")
    print()

    print("=== SECTION 4: mxfs-CCph markers, test1/8/16/24/32 ===")
    print("per-node CCph marker counts (all 32 nodes):")
    for i in range(1, 33):
        node = f"test{i}"
        print(f"  {node}: {ccph_count_per_node.get(node, 0)}")
    print()
    print("datawrite/md5write durations (journal-ts deltas), selected nodes:")
    print("  datawrite_dur = ts(datawrite-done) - ts(barrier-ready-done)")
    print("  md5write_dur  = ts(md5write-done) - ts(datawrite-done)")
    for node in ["test1", "test8", "test16", "test24", "test32"]:
        phases = ccph_per_node.get(node, {})
        br = phases.get("barrier-ready-done")
        dw = phases.get("datawrite-done")
        md5 = phases.get("md5write-done")
        dw_dur = (dw - br) if (br is not None and dw is not None) else None
        md5_dur = (md5 - dw) if (dw is not None and md5 is not None) else None
        print(f"  {node}: phases_present={sorted(phases.keys())} "
              f"datawrite_dur_s={dw_dur} md5write_dur_s={md5_dur}")
    print()
    print(f"malformed mxfs-CCph lines skipped: {malformed['ccph']}")
    print()
    print(f"TOTAL LINES PARSED ACROSS {len(files)} NODE FILES: {total_lines}")

if __name__ == "__main__":
    main()
