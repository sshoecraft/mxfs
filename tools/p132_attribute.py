#!/usr/bin/env python3
"""p132_attribute.py -- attribute the cost of a create from P132-CREATE lines.

    tools/p132_attribute.py <evidence-dir-or-kernlog>...

Reads `mxfs: P132-CREATE` probe lines out of node kernel logs (plain or .gz)
and prints where the time in a create actually went.

Why this exists.  At 32 nodes a create into one shared directory costs ~27 ms,
and a create into a PRIVATE per-node directory at the same node count costs
about the same -- 6x what it costs at one node, with nothing shared but the
mount.  That per-create cost, not the directory lock, is what sets the ceiling
on the shared-LUN create workload: with creates globally serialised behind one
exclusive grant, removing ALL lock-handoff cost buys at most 1/(1-f) where f is
the handoff fraction of the critical path, and f measured 5-16%.  So the
question that decides the defect is "where do the 27 ms go", and until sess481
the one probe that could answer it ran on directory creates only.

The three fields this tool exists to separate are stamped at call boundaries
inside a single function (xfs/xfs_inode.c, xfs_create), so they are mutually
exclusive by construction:

    res_ms  transaction reservation -- a full log blocks here
    dlk_ms  the parent directory's cross-node DLM grant (the queue wait)
    dia_ms  inode allocation, which carries the allocation-group grant

`other_ms` is the unattributed remainder of pre_ms and is reported explicitly
rather than folded away: a decomposition whose remainder is large is a
decomposition that has not yet found the cost, and saying so is the point.
"""
import gzip
import os
import re
import sys

LINE = re.compile(r"mxfs: P132-CREATE\s+(.*)")
KV = re.compile(r"(\w+)=(-?\d+)")

# printed in this order; the exclusive sub-phases of pre_ms first.  rfr/icr/
# mrg/cc exist from 0.69.4 on (they split what older lines report only as
# other_ms); on older lines they read 0 and other_ms carries the whole span.
SUBPHASES = ["res_ms", "dlk_ms", "dia_ms", "rfr_ms", "lkp_ms", "icr_ms",
             "mrg_ms", "cc_ms"]   # lkp_ms exists from 0.69.5 on
FIELDS = SUBPHASES + ["other_ms",
          "pre_ms", "commit_ms", "dirsig_ms", "pub_ms", "pdur_ms", "total_ms"]


def opener(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def collect(paths):
    """Return (rows, files_read, files_with_hits)."""
    rows, read, hit = [], 0, 0
    for p in paths:
        try:
            with opener(p) as f:
                read += 1
                n0 = len(rows)
                for ln in f:
                    m = LINE.search(ln)
                    if not m:
                        continue
                    d = {k: int(v) for k, v in KV.findall(m.group(1))}
                    if "total_ms" not in d:
                        continue
                    # the remainder of pre_ms that the stamped sub-phases
                    # do not explain
                    d["other_ms"] = max(0, d.get("pre_ms", 0)
                                        - sum(d.get(k, 0) for k in SUBPHASES))
                    d["node"] = os.path.basename(p)
                    rows.append(d)
                if len(rows) > n0:
                    hit += 1
        except OSError as e:
            print("  (unreadable: %s: %s)" % (p, e), file=sys.stderr)
    return rows, read, hit


def pct(sorted_vals, q):
    if not sorted_vals:
        return 0
    i = min(len(sorted_vals) - 1, int(len(sorted_vals) * q))
    return sorted_vals[i]


def report(label, rows):
    print("== %s: n=%d creates ==" % (label, len(rows)))
    if not rows:
        print("   NO P132-CREATE LINES. The probe was not armed, or no create "
              "reached the threshold. This is not a measurement of a fast "
              "filesystem -- it is the absence of a measurement.")
        return
    tot = sum(r["total_ms"] for r in rows)
    print("   %-10s %8s %10s %7s %7s %7s %7s  %s"
          % ("field", "n", "sum_ms", "mean", "p50", "p90", "max", "share"))
    for f in FIELDS:
        vals = sorted(r.get(f, 0) for r in rows)
        s = sum(vals)
        share = ("%5.1f%%" % (100.0 * s / tot)) if tot else "    -"
        print("   %-10s %8d %10d %7.1f %7d %7d %7d  %s"
              % (f, len(vals), s, s / float(len(vals)), pct(vals, 0.5),
                 pct(vals, 0.9), vals[-1], share))
    print("   NOTE: res/dlk/dia/rfr/icr/mrg/cc/other are the exclusive parts of "
          "pre_ms; their shares are of total_ms, so they sum to pre_ms's share, "
          "not 100%.")

    ags = {}
    for r in rows:
        ags.setdefault(r.get("ag", -1), []).append(r["total_ms"])
    if len(ags) > 1:
        print("   per-AG total_ms (allocation-group contention shows up here):")
        for ag in sorted(ags):
            v = sorted(ags[ag])
            print("     ag=%-4d n=%-6d mean=%7.1f p50=%-6d p90=%-6d max=%d"
                  % (ag, len(v), sum(v) / float(len(v)), pct(v, 0.5),
                     pct(v, 0.9), v[-1]))
    print()


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    paths = []
    for a in args:
        if os.path.isdir(a):
            for n in sorted(os.listdir(a)):
                if n.startswith("kernlog_") or n.endswith(".gz"):
                    paths.append(os.path.join(a, n))
        else:
            paths.append(a)
    if not paths:
        sys.exit("no kernel logs found in: %s" % " ".join(args))

    rows, read, hit = collect(paths)
    print("read %d file(s), %d contained P132-CREATE lines" % (read, hit))
    if read and not hit:
        print("REFUSING TO REPORT: not one input carried the probe. Arm "
              "mxfs.create_cost_ms on the nodes and confirm the read-back "
              "before running the workload.")
        return 2
    report("ALL creates", rows)
    files = [r for r in rows if r.get("dir", 0) == 0]
    dirs = [r for r in rows if r.get("dir", 0) == 1]
    if files and dirs:
        report("FILE creates (dir=0)", files)
        report("DIRECTORY creates (dir=1)", dirs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
