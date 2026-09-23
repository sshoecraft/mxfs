#!/usr/bin/env python3
"""p132_phase_summary.py -- phase/tenure/node breakdown of P132-CREATE lines.

    tools/p132_phase_summary.py <evidence-dir-or-kernlog>...

Input: one or more evidence directories (every kernlog_test*.gz / kernlog_*
inside is read) or explicit kernlog file paths (plain or .gz), exactly like
tools/p132_attribute.py.  Reuses that module's collect()/pct() rather than
re-implementing the parse, so both tools stay consistent about what counts
as a valid P132-CREATE line.

Output, for the given set of lines as a single arm:
  1. full-field table (res/dlk/dia/other/pre, commit/dirsig/pub/pdur/
     post_other, total) -- mean, p50, p90, max, share of sum(total_ms).
     post_other_ms = total - pre - commit - dirsig - pub - pdur, the
     unattributed remainder of the POST-commit path, reported explicitly
     for the same reason p132_attribute.py reports other_ms explicitly:
     an unnamed remainder is real cost until something claims it.
  2. the same table restricted to IN-TENURE creates (dlk_ms < 5 -- the
     node already held the parent directory's DLM grant), plus the split
     count in-tenure vs first-in-tenure (dlk_ms >= 5).
  3. for in-tenure creates only: the single field with the largest mean,
     and mean total_ms -- the serialized per-create cost under a held
     directory lock.
  4. distribution of dir= (0/1) and comm= values; count of distinct ag=
     values and the top 5 by n.
  5. per-node table (comm=<file's node file name>): n, mean total_ms,
     mean dlk_ms, in-tenure mean total_ms.

Run once per arm (point it at that arm's evidence dir); this tool does not
itself know which directory is "shared" and which is "private" -- that is
determined by the caller from the driving log's STAGE/EVIDENCE lines.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p132_attribute as base  # reuse collect()/pct(): same parse, same rules

TENURE_THRESHOLD_MS = 5

FULL_FIELDS = ["res_ms", "dlk_ms", "dia_ms",
               "rfr_ms", "lkp_ms", "icr_ms", "mrg_ms", "cc_ms",   # 0.69.4+ stamps (lkp 0.69.5+)
               "other_ms", "pre_ms",
               "commit_ms", "dirsig_ms", "pub_ms", "pdur_ms",
               "post_other_ms", "total_ms",
               "lkp_fua", "lkp_fua_ms", "lkp_rd"]   # 0.70.13+: what the lookup term is


def add_post_other(rows):
    for r in rows:
        r["post_other_ms"] = max(0, r.get("total_ms", 0)
                                  - r.get("pre_ms", 0)
                                  - r.get("commit_ms", 0)
                                  - r.get("dirsig_ms", 0)
                                  - r.get("pub_ms", 0)
                                  - r.get("pdur_ms", 0))


def field_stats(rows, field):
    vals = sorted(r.get(field, 0) for r in rows)
    n = len(vals)
    s = sum(vals)
    mean = s / float(n) if n else 0.0
    return dict(n=n, sum=s, mean=mean, p50=base.pct(vals, 0.5),
                p90=base.pct(vals, 0.9), max=(vals[-1] if vals else 0))


def print_table(label, rows):
    print("-- %s: n=%d --" % (label, len(rows)))
    if not rows:
        print("   (no rows)")
        return
    tot = sum(r["total_ms"] for r in rows)
    print("   %-14s %8s %10s %8s %7s %7s %7s  %s"
          % ("field", "n", "sum_ms", "mean", "p50", "p90", "max", "share"))
    for f in FULL_FIELDS:
        st = field_stats(rows, f)
        share = ("%5.1f%%" % (100.0 * st["sum"] / tot)) if tot else "    -"
        print("   %-14s %8d %10d %8.1f %7d %7d %7d  %s"
              % (f, st["n"], st["sum"], st["mean"], st["p50"], st["p90"],
                 st["max"], share))


def parse_comm(paths):
    """Second pass: comm=<s> is not numeric, so base.KV (\\d+ only) drops
    it. Re-scan the same files for the string value, aligned by line order
    is not attempted -- instead we just tally comm across all matched
    P132-CREATE lines, which is all the report needs."""
    import re
    import gzip
    counts = {}
    creline = re.compile(r"mxfs: P132-CREATE\s+(.*)")
    commre = re.compile(r"\bcomm=(\S+)")
    for p in paths:
        try:
            op = gzip.open(p, "rt", errors="replace") if p.endswith(".gz") \
                else open(p, "r", errors="replace")
            with op as f:
                for ln in f:
                    m = creline.search(ln)
                    if not m:
                        continue
                    cm = commre.search(m.group(1))
                    if cm:
                        counts[cm.group(1)] = counts.get(cm.group(1), 0) + 1
        except OSError:
            pass
    return counts


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

    rows, read, hit = base.collect(paths)
    print("read %d file(s), %d contained P132-CREATE lines, %d rows parsed"
          % (read, hit, len(rows)))
    if read and not hit:
        print("REFUSING TO REPORT: not one input carried the probe.")
        return 2
    add_post_other(rows)

    # 1. full table, all rows
    print_table("ALL creates", rows)
    print()

    # 2. in-tenure split
    tenure = [r for r in rows if r.get("dlk_ms", 0) < TENURE_THRESHOLD_MS]
    first = [r for r in rows if r.get("dlk_ms", 0) >= TENURE_THRESHOLD_MS]
    print("in-tenure (dlk_ms<%d): n=%d  first-in-tenure (dlk_ms>=%d): n=%d"
          % (TENURE_THRESHOLD_MS, len(tenure), TENURE_THRESHOLD_MS, len(first)))
    print_table("IN-TENURE creates", tenure)
    print()

    # 3. largest-mean field, in-tenure only
    if tenure:
        means = {f: field_stats(tenure, f)["mean"]
                 for f in FULL_FIELDS if f != "total_ms"}
        top_field = max(means, key=means.get)
        tot_mean = field_stats(tenure, "total_ms")["mean"]
        print("in-tenure largest-mean field: %s (mean=%.2f ms); "
              "in-tenure mean total_ms=%.2f ms"
              % (top_field, means[top_field], tot_mean))
    else:
        print("in-tenure largest-mean field: n/a (no in-tenure rows)")
    print()

    # 4. dir=, comm=, ag= distributions
    dirs = {}
    for r in rows:
        dirs[r.get("dir", -1)] = dirs.get(r.get("dir", -1), 0) + 1
    print("dir= distribution: %s"
          % ", ".join("%s=%d" % (k, v) for k, v in sorted(dirs.items())))

    comm_counts = parse_comm(paths)
    print("comm= distribution (%d distinct): %s"
          % (len(comm_counts),
             ", ".join("%s=%d" % (k, v) for k, v in
                        sorted(comm_counts.items(), key=lambda kv: -kv[1]))))

    ags = {}
    for r in rows:
        ags[r.get("ag", -1)] = ags.get(r.get("ag", -1), 0) + 1
    top5 = sorted(ags.items(), key=lambda kv: -kv[1])[:5]
    print("ag= distinct values: %d; top 5 by n: %s"
          % (len(ags), ", ".join("ag=%s(n=%d)" % (k, v) for k, v in top5)))
    print()

    # 5. per-node table
    nodes = {}
    for r in rows:
        nodes.setdefault(r.get("node", "?"), []).append(r)
    print("-- per-node (n=%d nodes) --" % len(nodes))
    print("   %-22s %6s %10s %10s %14s"
          % ("node", "n", "mean_tot", "mean_dlk", "tenure_mean_tot"))
    for node in sorted(nodes, key=lambda s: (len(s), s)):
        nr = nodes[node]
        n = len(nr)
        mean_tot = sum(r["total_ms"] for r in nr) / float(n) if n else 0.0
        mean_dlk = sum(r.get("dlk_ms", 0) for r in nr) / float(n) if n else 0.0
        tnr = [r for r in nr if r.get("dlk_ms", 0) < TENURE_THRESHOLD_MS]
        tmean = (sum(r["total_ms"] for r in tnr) / float(len(tnr))
                  if tnr else 0.0)
        print("   %-22s %6d %10.1f %10.1f %14.1f"
              % (node, n, mean_tot, mean_dlk, tmean))
    return 0


if __name__ == "__main__":
    sys.exit(main())
