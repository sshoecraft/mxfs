#!/usr/bin/env python3
"""dirtenure_summary.py -- summarize P483-DIRTENURE probe lines from node kernel logs.

    tools/dirtenure_summary.py <evidence-dir-or-kernlog>...

Input: either one or more paths to an evidence directory (as produced by a
fleet run.sh row, e.g. tests/evidence/run_<label>_<timestamp>/) containing
`kernlog_<node>.gz` (or plain `kernlog_<node>`) files, or a list of
individual kernlog(.gz) file paths given directly on the command line.  Any
mix of directories and files is accepted; directories are scanned
non-recursively for files matching `kernlog_*` (gzipped or plain).

Parses lines of the form:

    mxfs: P483-DIRTENURE parent=<ino> epoch=<n> creates=<K> wall_ms=<ms>
        mean_ms=<ms> gap_ms=<ms> next_epoch=<n> endsrc=<n> comm=<s> -- ...

One line is emitted per TENURE (one ownership episode of a directory's EX
grant).  creates=K is how many creates completed in that tenure, wall_ms is
the tenure's wall clock, and gap_ms is the wait between the last create of
the PREVIOUS tenure of that directory (on any node) and the first create of
THIS tenure -- i.e. the cross-node queueing delay for the grant.

Output (to stdout):

  1. Per node, per parent ino: tenure count, sum(creates), sum(wall_ms),
     sum(gap_ms), K [p50/mean/max], gap_ms [p50/mean/max].
  2. The fleet's "shared" parent ino is identified as the parent ino present
     in every node's log with the largest fleet-wide sum(creates) (ties
     broken by ino), and reported are: total tenures, total creates, a
     histogram of K in buckets {1, 2-3, 4-7, 8-15, 16-31, 32+}, a histogram
     of gap_ms in buckets {<30ms, 30-300, 300-1000, 1000-3000, >=3000},
     the fleet-wide fraction of (gap_ms + wall_ms) that is gap_ms (queue
     wait) vs wall_ms (in-tenure), and the mean of the per-tenure mean_ms
     field (both a simple mean-of-means and a creates-weighted mean, i.e.
     sum(wall_ms)/sum(creates)).
  3. The endsrc= value distribution across all P483 lines (fleet-wide),
     for the shared parent and for all parents combined.

All counts state the exact denominator (lines matched, files scanned,
parse failures skipped) -- see the "Parse notes" section printed at the end
of the report.  Malformed lines (missing an expected field) are skipped and
counted, never silently dropped without a count.
"""
import gzip
import os
import re
import sys
from collections import defaultdict

LINE = re.compile(r"mxfs:\s*P483-DIRTENURE\s+(.*)")
KV = re.compile(r"(\w+)=(-?\d+)")
COMM = re.compile(r"comm=(\S+)")

INT_FIELDS = ["parent", "epoch", "creates", "wall_ms", "mean_ms", "gap_ms",
              "next_epoch", "endsrc"]

K_BUCKETS = [
    ("1", lambda k: k == 1),
    ("2-3", lambda k: 2 <= k <= 3),
    ("4-7", lambda k: 4 <= k <= 7),
    ("8-15", lambda k: 8 <= k <= 15),
    ("16-31", lambda k: 16 <= k <= 31),
    ("32+", lambda k: k >= 32),
]

GAP_BUCKETS = [
    ("<30ms", lambda g: g < 30),
    ("30-300", lambda g: 30 <= g < 300),
    ("300-1000", lambda g: 300 <= g < 1000),
    ("1000-3000", lambda g: 1000 <= g < 3000),
    (">=3000", lambda g: g >= 3000),
]


def node_name_from_path(path):
    base = os.path.basename(path)
    base = base[:-3] if base.endswith(".gz") else base
    if base.startswith("kernlog_"):
        base = base[len("kernlog_"):]
    return base


def iter_kernlog_files(args):
    files = []
    for a in args:
        if os.path.isdir(a):
            for name in sorted(os.listdir(a)):
                if name.startswith("kernlog_") and (
                    name.endswith(".gz") or "." not in name[len("kernlog_"):]
                ):
                    full = os.path.join(a, name)
                    if os.path.isfile(full):
                        files.append(full)
        elif os.path.isfile(a):
            files.append(a)
        else:
            print("WARNING: path not found, skipped: %s" % a, file=sys.stderr)
    return files


def open_maybe_gz(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def parse_file(path, records, stats):
    node = node_name_from_path(path)
    stats["files_scanned"] += 1
    with open_maybe_gz(path) as fh:
        for raw in fh:
            stats["lines_scanned"] += 1
            m = LINE.search(raw)
            if not m:
                continue
            stats["p483_lines_matched"] += 1
            rest = m.group(1)
            kv = dict(KV.findall(rest))
            cm = COMM.search(rest)
            missing = [f for f in INT_FIELDS if f not in kv]
            if missing:
                stats["p483_parse_failed"] += 1
                continue
            rec = {f: int(kv[f]) for f in INT_FIELDS}
            rec["comm"] = cm.group(1) if cm else ""
            rec["node"] = node
            records.append(rec)


def pctl(sorted_vals, p):
    if not sorted_vals:
        return 0
    idx = min(len(sorted_vals) - 1, max(0, int(round(p * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


def fmt_stats(vals):
    if not vals:
        return "n=0"
    s = sorted(vals)
    return "n=%d p50=%s mean=%.1f max=%s" % (
        len(vals), pctl(s, 0.5), sum(vals) / len(vals), s[-1]
    )


def main(argv):
    if not argv:
        print(__doc__)
        return 1

    files = iter_kernlog_files(argv)
    if not files:
        print("No kernlog files found in given paths.", file=sys.stderr)
        return 1

    records = []
    stats = defaultdict(int)
    for f in files:
        parse_file(f, records, stats)

    if not records:
        print("No P483-DIRTENURE lines parsed from %d file(s) (%d lines scanned)." % (
            stats["files_scanned"], stats["lines_scanned"]))
        return 0

    nodes = sorted(set(r["node"] for r in records))

    # ---- Section 1: per-node, per-parent ----
    print("=" * 100)
    print("SECTION 1: per-node, per-parent tenure summary")
    print("=" * 100)
    per_node_parent = defaultdict(list)
    for r in records:
        per_node_parent[(r["node"], r["parent"])].append(r)

    for node in nodes:
        parents = sorted(set(p for (n, p) in per_node_parent if n == node))
        print("\n-- node=%s (parents seen: %d) --" % (node, len(parents)))
        for parent in parents:
            recs = per_node_parent[(node, parent)]
            k_vals = [r["creates"] for r in recs]
            gap_vals = [r["gap_ms"] for r in recs]
            wall_vals = [r["wall_ms"] for r in recs]
            print("  parent=%-12d tenures=%-4d sum_creates=%-6d sum_wall_ms=%-8d "
                  "sum_gap_ms=%-9d K[%s] gap_ms[%s]" % (
                      parent, len(recs), sum(k_vals), sum(wall_vals), sum(gap_vals),
                      fmt_stats(k_vals), fmt_stats(gap_vals)))

    # ---- identify the shared parent ----
    # present in every node's log, and with the largest fleet-wide sum(creates)
    parent_nodes = defaultdict(set)
    parent_creates = defaultdict(int)
    parent_tenures = defaultdict(int)
    for r in records:
        parent_nodes[r["parent"]].add(r["node"])
        parent_creates[r["parent"]] += r["creates"]
        parent_tenures[r["parent"]] += 1

    n_nodes = len(nodes)
    candidates = [p for p, ns in parent_nodes.items() if len(ns) == n_nodes]
    if candidates:
        shared_parent = max(candidates, key=lambda p: (parent_creates[p], -p))
    else:
        # fall back: parent present in the most nodes, tie-broken by creates
        shared_parent = max(parent_nodes.keys(),
                             key=lambda p: (len(parent_nodes[p]), parent_creates[p], -p))

    print("\nShared-directory parent selected: parent=%d "
          "(present in %d of %d node logs, fleet sum(creates)=%d, fleet tenures=%d)" % (
              shared_parent, len(parent_nodes[shared_parent]), n_nodes,
              parent_creates[shared_parent], parent_tenures[shared_parent]))
    if len(parent_nodes[shared_parent]) != n_nodes:
        print("  NOTE: shared parent is NOT present in all %d node logs "
              "(no single parent ino was present in all logs); this is the closest "
              "candidate by node coverage and creates volume." % n_nodes)

    other_parents = sorted(
        (p for p in parent_nodes if p != shared_parent),
        key=lambda p: -parent_creates[p]
    )
    if other_parents:
        print("\nOther parent inos seen fleet-wide (not selected as shared), by sum(creates):")
        for p in other_parents:
            print("  parent=%-12d nodes=%-3d sum_creates=%-6d tenures=%-4d" % (
                p, len(parent_nodes[p]), parent_creates[p], parent_tenures[p]))

    # ---- Section 2: fleet-wide, shared parent ----
    print("\n" + "=" * 100)
    print("SECTION 2: fleet-wide summary for shared parent=%d" % shared_parent)
    print("=" * 100)
    shared_recs = [r for r in records if r["parent"] == shared_parent]
    k_vals = [r["creates"] for r in shared_recs]
    gap_vals = [r["gap_ms"] for r in shared_recs]
    wall_vals = [r["wall_ms"] for r in shared_recs]
    mean_field_vals = [r["mean_ms"] for r in shared_recs]

    total_tenures = len(shared_recs)
    total_creates = sum(k_vals)
    total_wall = sum(wall_vals)
    total_gap = sum(gap_vals)

    print("total_tenures=%d total_creates=%d sum_wall_ms=%d sum_gap_ms=%d" % (
        total_tenures, total_creates, total_wall, total_gap))

    print("\nK (creates per tenure) histogram, n=%d:" % len(k_vals))
    for label, pred in K_BUCKETS:
        c = sum(1 for k in k_vals if pred(k))
        pct = 100.0 * c / len(k_vals) if k_vals else 0.0
        print("  K=%-6s count=%-5d (%.1f%%)" % (label, c, pct))

    print("\ngap_ms histogram, n=%d:" % len(gap_vals))
    for label, pred in GAP_BUCKETS:
        c = sum(1 for g in gap_vals if pred(g))
        pct = 100.0 * c / len(gap_vals) if gap_vals else 0.0
        print("  gap_ms=%-10s count=%-5d (%.1f%%)" % (label, c, pct))

    denom = total_wall + total_gap
    gap_frac = (100.0 * total_gap / denom) if denom else 0.0
    wall_frac = (100.0 * total_wall / denom) if denom else 0.0
    print("\nOf total per-tenure (wall_ms + gap_ms) = %d ms fleet-wide for the shared parent:" % denom)
    print("  gap_ms (queue wait)  = %d ms (%.1f%%)" % (total_gap, gap_frac))
    print("  wall_ms (in-tenure)  = %d ms (%.1f%%)" % (total_wall, wall_frac))

    mean_of_means = sum(mean_field_vals) / len(mean_field_vals) if mean_field_vals else 0.0
    weighted_mean = (total_wall / total_creates) if total_creates else 0.0
    print("\nmean_ms within tenure (shared parent):")
    print("  simple mean of per-tenure mean_ms field = %.2f ms (n=%d tenures)" % (
        mean_of_means, len(mean_field_vals)))
    print("  creates-weighted mean (sum wall_ms / sum creates) = %.2f ms (n=%d creates)" % (
        weighted_mean, total_creates))

    # ---- Section 3: P132-CREATE counts + p132_attribute.py ----
    print("\n" + "=" * 100)
    print("SECTION 3: P132-CREATE line counts per node")
    print("=" * 100)
    p132_total = 0
    p132_re = re.compile(r"P132-CREATE")
    for f in files:
        node = node_name_from_path(f)
        cnt = 0
        with open_maybe_gz(f) as fh:
            for raw in fh:
                if p132_re.search(raw):
                    cnt += 1
        p132_total += cnt
        print("  node=%-10s P132-CREATE_count=%d" % (node, cnt))
    print("  TOTAL P132-CREATE lines across %d files = %d" % (len(files), p132_total))

    # ---- Section 4: endsrc distribution ----
    print("\n" + "=" * 100)
    print("SECTION 4: endsrc= value distribution")
    print("=" * 100)
    endsrc_shared = defaultdict(int)
    for r in shared_recs:
        endsrc_shared[r["endsrc"]] += 1
    print("Shared parent=%d (n=%d tenures):" % (shared_parent, total_tenures))
    for v, c in sorted(endsrc_shared.items(), key=lambda x: -x[1]):
        print("  endsrc=%-8d count=%-5d (%.1f%%)" % (v, c, 100.0 * c / total_tenures))

    endsrc_all = defaultdict(int)
    for r in records:
        endsrc_all[r["endsrc"]] += 1
    print("\nAll parents combined (n=%d tenures):" % len(records))
    for v, c in sorted(endsrc_all.items(), key=lambda x: -x[1]):
        print("  endsrc=%-8d count=%-5d (%.1f%%)" % (v, c, 100.0 * c / len(records)))

    # ---- parse notes ----
    print("\n" + "=" * 100)
    print("Parse notes")
    print("=" * 100)
    print("files_scanned=%d lines_scanned=%d p483_lines_matched=%d p483_parse_failed=%d "
          "p483_records_used=%d" % (
              stats["files_scanned"], stats["lines_scanned"], stats["p483_lines_matched"],
              stats["p483_parse_failed"], len(records)))

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
