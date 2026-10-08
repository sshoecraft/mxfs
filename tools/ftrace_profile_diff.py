#!/usr/bin/env python3
"""ftrace_profile_diff.py — what happened between two snapshots of the ftrace
function profiler, as tests/pve_pair_profile.sh writes them
(<host>.profile.<n>: every CPU's trace_stat table, totals since the start).

The profiler's counters run on from the moment it starts, so a workload phase
is the difference of the snapshot taken just before it and the one just after.
Each function's calls and wall time (sleep and callees included) are summed
over the CPUs in each snapshot and subtracted.

Usage: tools/ftrace_profile_diff.py BEFORE AFTER [--per N]
  --per N   also print each function's calls and wall time divided by N
            (N = the operations the phase did: files created, entries walked)
"""
import argparse
import collections
import re

UNIT = {"ns": 1e-6, "us": 1e-3, "ms": 1.0, "s": 1e3}
ROW = re.compile(r"^\s*(\S+)\s+(\d+)\s+([\d.]+)\s+(ns|us|ms|s)\b")


def load(path):
    hits, tot = collections.Counter(), collections.Counter()
    with open(path, errors="replace") as f:
        for line in f:
            m = ROW.match(line)
            if not m or m.group(1) == "Function":
                continue
            hits[m.group(1)] += int(m.group(2))
            tot[m.group(1)] += float(m.group(3)) * UNIT[m.group(4)]
    return hits, tot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--per", type=float, default=0)
    a = ap.parse_args()
    h0, t0 = load(a.before)
    h1, t1 = load(a.after)
    rows = []
    for fn in set(h1) | set(h0):
        dh = h1[fn] - h0[fn]
        dt = t1[fn] - t0[fn]
        if dh > 0:
            rows.append((dt, dh, fn))
    rows.sort(reverse=True)
    hdr = f"{'function':36s} {'calls':>8s} {'wall ms':>10s} {'mean ms':>9s}"
    if a.per:
        hdr += f" {'calls/op':>9s} {'ms/op':>8s}"
    print(hdr)
    for dt, dh, fn in rows:
        line = f"{fn:36s} {dh:8d} {dt:10.1f} {dt / dh:9.2f}"
        if a.per:
            line += f" {dh / a.per:9.2f} {dt / a.per:8.2f}"
        print(line)


if __name__ == "__main__":
    main()
