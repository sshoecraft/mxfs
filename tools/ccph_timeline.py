#!/usr/bin/env python3
"""ccph_timeline.py — per-node phase timeline of one crash_consistency run.

tests/suite/crash_consistency.sh stamps `mxfs-CCph rank=R PHASE=<name>` into
the kernel log at every phase boundary.  Given a directory of per-node kernel
log captures (kernlog_test<N>.gz or .txt, as run.sh and the chain sweeps
write them), this prints, per node, the wall seconds from that node's LAST
PHASE=start to each later marker, then the fleet distribution of the two
phases that carry the row's cost: the durable write phase (start ->
md5write-done: 50 O_SYNC creates + 50 sidecar creates in the shared
directory) and the cold verify phase (dropcaches-done -> verify-done: 200
cold file reads + 200 sidecar reads).  A node whose run ended before a marker
shows '-' for it, so a budget-exhausted row says WHERE it ran out.

Usage: tools/ccph_timeline.py <capture-dir>
"""
import glob
import gzip
import os
import re
import sys
import time

PHASES = ["start", "barrier-ready-done", "datawrite-done", "md5write-done",
          "barrier-written-done", "dropcaches-done", "verify-done",
          "count-done", "barrier-done-done"]
MARK = re.compile(r"^\[(?:\s*[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+(\d+):(\d+):(\d+)\s+\d+|\s*(\d+\.\d+))\]"
                  r".*mxfs-CCph rank=(\d+) PHASE=([a-z0-9-]+)")


def stamp(m):
    """seconds within the day (rig logs carry 'Fri Sep  4 06:57:55 2026') or
    the raw dmesg seconds; both are monotonic inside one capture."""
    if m.group(4):
        return float(m.group(4))
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))


def node_num(path):
    m = re.search(r"test(\d+)", os.path.basename(path))
    return int(m.group(1)) if m else 0


def read_lines(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", errors="replace") as f:
        for line in f:
            yield line


def main():
    if len(sys.argv) != 2 or not os.path.isdir(sys.argv[1]):
        sys.stderr.write(__doc__)
        return 2
    d = sys.argv[1]
    files = sorted(glob.glob(os.path.join(d, "kernlog_test*.gz")) +
                   glob.glob(os.path.join(d, "kernlog_test*.txt")) +
                   glob.glob(os.path.join(d, "ctx_test*.gz")), key=node_num)
    if not files:
        print(f"no kernlog_test*/ctx_test* captures in {d}")
        return 1
    rows = {}
    for path in files:
        marks = {}
        last_start = None
        for line in read_lines(path):
            m = MARK.search(line)
            if not m:
                continue
            ph = m.group(6)
            t = stamp(m)
            if ph == "start":
                marks = {"start": t}
                last_start = t
            elif last_start is not None:
                marks.setdefault(ph, t)  # first after the last start
        rows[node_num(path)] = marks
    print(f"capture {d}: {len(rows)} node logs")
    hdr = "node  " + " ".join(f"{p[:9]:>9}" for p in PHASES[1:]) + "   write_s verify_s"
    print(hdr)
    writes, verifies, stuck = [], [], {}
    for n in sorted(rows):
        mk = rows[n]
        if "start" not in mk:
            print(f"{n:<5} (no PHASE=start)")
            continue
        s = mk["start"]
        cells = []
        for p in PHASES[1:]:
            cells.append(f"{mk[p] - s:9.1f}" if p in mk else f"{'-':>9}")
        w = mk["md5write-done"] - s if "md5write-done" in mk else None
        v = (mk["verify-done"] - mk["dropcaches-done"]
             if "verify-done" in mk and "dropcaches-done" in mk else None)
        if w is not None:
            writes.append(w)
        if v is not None:
            verifies.append(v)
        last = [p for p in PHASES if p in mk][-1]
        if last != "barrier-done-done":
            stuck[last] = stuck.get(last, 0) + 1
        print(f"{n:<5} " + " ".join(cells) +
              f"   {w if w is not None else '-':>7} {v if v is not None else '-':>8}")

    def dist(name, xs):
        if not xs:
            print(f"{name}: n=0")
            return
        xs = sorted(xs)
        p50 = xs[len(xs) // 2]
        print(f"{name}: n={len(xs)} min={xs[0]:.1f} p50={p50:.1f} max={xs[-1]:.1f} "
              f"mean={sum(xs) / len(xs):.1f}")

    print()
    dist("write_phase_s (start->md5write-done)", writes)
    dist("verify_phase_s (dropcaches-done->verify-done)", verifies)
    if stuck:
        print("nodes whose LAST marker is not barrier-done-done (where the run ended): " +
              ", ".join(f"{k}={v}" for k, v in sorted(stuck.items())))
    else:
        print("all nodes reached barrier-done-done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
