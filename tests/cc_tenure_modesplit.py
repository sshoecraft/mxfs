#!/usr/bin/env python3
"""
cc_tenure_modesplit.py — MODE-SPLIT timeline analysis of the shared-directory
DLM lock (P138-ACQ / P138-BAST kernel trace lines) for the crash_consistency
fleet run.

Usage: cc_tenure_modesplit.py <evidence_dir>

<evidence_dir> must contain testN.log files (N = node number), each holding
grepped `journalctl -k -o short-precise` lines matching:
  P138-ACQ|P138-BAST|P138-ACQSUM|mxfs-CCph rank=

Only P138-ACQ and P138-BAST lines are parsed for this report; P138-ACQSUM and
mxfs-CCph rank= lines are ignored (not malformed — out of scope for this
report).

Persisted so it survives a reboot (tests/ harness, not /tmp). See sess436 evidence dir
tests/evidence/sess436_tenure_modesplit/ for the run this was built against.
"""
import sys
import re
import os
import glob
import statistics
from collections import defaultdict

def pick_target_ino(evdir, explicit=None):
    """sess436: the shared dir's inode number changes with every mkfs; pick the
    most frequent ino= across all P138-ACQ lines unless argv[2] names one."""
    import collections, glob as _g, os as _o, re as _re
    if explicit:
        return int(explicit)
    cnt = collections.Counter()
    for f in _g.glob(_o.path.join(evdir, "test*.log")):
        for line in open(f, errors="replace"):
            if "P138-ACQ " in line:
                m = _re.search(r" ino=(\d+) ", line)
                if m and m.group(1) != "0":
                    cnt[int(m.group(1))] += 1
    return cnt.most_common(1)[0][0] if cnt else 0

TARGET_INO_DEFAULT = 25165952

ACQ_RE = re.compile(
    r'mxfs: P138-ACQ type=(?P<type>\d+) ino=(?P<ino>\d+) ag=(?P<ag>\d+) '
    r'mode=(?P<mode>\d+) elapsed_ms=(?P<elapsed_ms>\d+) rc=(?P<rc>-?\d+) '
    r'realms=(?P<realms>\d+)'
)
BAST_RE = re.compile(
    r'mxfs: P138-BAST ino=(?P<ino>\d+) dur_us=(?P<dur_us>\d+) '
    r'dir=(?P<dir>-?\d+) clean=(?P<clean>-?\d+) '
    r'sa=(?P<sa>\d+) sb=(?P<sb>\d+) b1=(?P<b1>\d+) b2=(?P<b2>\d+) '
    r'sc=(?P<sc>\d+) sd=(?P<sd>\d+) su=(?P<su>\d+) sw=(?P<sw>\d+) '
    r'sx=(?P<sx>\d+) realns=(?P<realns>\d+)'
)
NODE_FROM_FNAME = re.compile(r'(test\d+)\.log$')


def pct(sorted_vals, p):
    """Nearest-rank percentile on an already-sorted list."""
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def dist(vals):
    if not vals:
        return dict(n=0, p10=None, p50=None, p90=None, p99=None, max=None)
    s = sorted(vals)
    return dict(
        n=len(s),
        p10=round(pct(s, 10), 2),
        p50=round(pct(s, 50), 2),
        p90=round(pct(s, 90), 2),
        p99=round(pct(s, 99), 2),
        max=s[-1],
    )


def fmt_dist(d, label=""):
    if d['n'] == 0:
        return f"{label}n=0 (no data)"
    return (f"{label}n={d['n']} p10={d['p10']} p50={d['p50']} "
            f"p90={d['p90']} p99={d['p99']} max={d['max']}")


def fmt_dist5(d, label=""):
    if d['n'] == 0:
        return f"{label}n=0 (no data)"
    return f"{label}n={d['n']} p50={d['p50']} p90={d['p90']} max={d['max']}"


def main():
    if len(sys.argv) not in (2, 3):
        print("usage: cc_tenure_modesplit.py <evidence_dir>", file=sys.stderr)
        sys.exit(2)
    evdir = sys.argv[1]
    global TARGET_INO
    TARGET_INO = pick_target_ino(evdir, sys.argv[2] if len(sys.argv) == 3 else None)

    logfiles = sorted(glob.glob(os.path.join(evdir, "test*.log")))
    if not logfiles:
        print(f"no test*.log files found in {evdir}", file=sys.stderr)
        sys.exit(1)

    acq_all = []          # all ACQ records, all inos
    bast_all = []          # all BAST records, all inos
    malformed = 0
    other_lines = 0        # ACQSUM / rank= / anything else the grep matched
    nodes_seen = set()

    for fpath in logfiles:
        m = NODE_FROM_FNAME.search(fpath)
        node = m.group(1) if m else os.path.basename(fpath)
        nodes_seen.add(node)
        with open(fpath, 'r', errors='replace') as f:
            for line in f:
                line = line.rstrip('\n')
                if not line:
                    continue
                if 'P138-ACQ ' in line:
                    m = ACQ_RE.search(line)
                    if not m:
                        malformed += 1
                        continue
                    g = m.groupdict()
                    acq_all.append(dict(
                        node=node,
                        type=int(g['type']), ino=int(g['ino']),
                        ag=int(g['ag']), mode=int(g['mode']),
                        elapsed_ms=int(g['elapsed_ms']), rc=int(g['rc']),
                        realms=int(g['realms']),
                    ))
                elif 'P138-BAST' in line:
                    m = BAST_RE.search(line)
                    if not m:
                        malformed += 1
                        continue
                    g = m.groupdict()
                    bast_all.append(dict(
                        node=node,
                        ino=int(g['ino']), dur_us=int(g['dur_us']),
                        dir=int(g['dir']), clean=int(g['clean']),
                        sa=int(g['sa']), sb=int(g['sb']),
                        b1=int(g['b1']), b2=int(g['b2']),
                        sc=int(g['sc']), sd=int(g['sd']),
                        su=int(g['su']), sw=int(g['sw']), sx=int(g['sx']),
                        realns=int(g['realns']),
                    ))
                else:
                    other_lines += 1

    all_nodes = sorted(nodes_seen, key=lambda n: int(n[4:]))

    acq_target = [a for a in acq_all if a['ino'] == TARGET_INO]
    bast_target = [b for b in bast_all if b['ino'] == TARGET_INO]

    print("=" * 78)
    print(f"cc_tenure_modesplit report — evidence dir: {evdir}")
    print(f"nodes: {len(all_nodes)}  ACQ lines (all ino): {len(acq_all)}  "
          f"BAST lines (all ino): {len(bast_all)}")
    print(f"ACQ target ino={TARGET_INO}: {len(acq_target)}   "
          f"BAST target ino={TARGET_INO}: {len(bast_target)}")
    print("=" * 78)

    # ---- section a ----
    print()
    print("--- (a) P138-ACQ mode split, ino=%d ---" % TARGET_INO)
    modes_target = sorted(set(a['mode'] for a in acq_target))
    modes_fleet = sorted(set(a['mode'] for a in acq_all))
    print(f"distinct mode values, target ino only: {modes_target}")
    print(f"distinct mode values, fleet-wide (all inos): {modes_fleet}")
    print()
    print("count by mode (target ino):")
    for mode in modes_target:
        n = sum(1 for a in acq_target if a['mode'] == mode)
        print(f"  mode={mode}: {n} of {len(acq_target)} grants")
    print()
    print("count by mode (fleet-wide, all inos):")
    for mode in modes_fleet:
        n = sum(1 for a in acq_all if a['mode'] == mode)
        print(f"  mode={mode}: {n} of {len(acq_all)} grants")
    print()
    print("per-mode elapsed_ms distribution (target ino):")
    for mode in modes_target:
        vals = [a['elapsed_ms'] for a in acq_target if a['mode'] == mode]
        print(f"  mode={mode}: {fmt_dist(dist(vals))}")
    print()
    print("per-mode per-node grant counts (target ino, min/median/max across "
          f"{len(all_nodes)} nodes; 0 counted for nodes with none of that mode):")
    for mode in modes_target:
        per_node_counts = []
        for node in all_nodes:
            c = sum(1 for a in acq_target if a['mode'] == mode and a['node'] == node)
            per_node_counts.append(c)
        print(f"  mode={mode}: min={min(per_node_counts)} "
              f"median={statistics.median(per_node_counts)} "
              f"max={max(per_node_counts)}  (n_nodes={len(per_node_counts)})")

    # ---- section b ----
    print()
    print(f"--- (b) fleet-sorted grant instants, ino={TARGET_INO}, first 120 ---")
    acq_sorted = sorted(acq_target, key=lambda a: a['realms'])
    print(f"total grants for target ino: {len(acq_sorted)} "
          f"(showing first {min(120, len(acq_sorted))})")
    if acq_sorted:
        t0 = acq_sorted[0]['realms']
        print(f"{'t_rel_ms':>10} {'node':>8} {'mode':>4} {'elapsed_ms':>10}")
        for a in acq_sorted[:120]:
            print(f"{a['realms'] - t0:>10} {a['node']:>8} {a['mode']:>4} "
                  f"{a['elapsed_ms']:>10}")

    # ---- section c ----
    print()
    print(f"--- (c) inter-grant gap distribution, ino={TARGET_INO} ---")
    if len(acq_sorted) >= 2:
        gaps_any = [acq_sorted[i + 1]['realms'] - acq_sorted[i]['realms']
                    for i in range(len(acq_sorted) - 1)]
        print(f"gaps between consecutive grants, ANY mode: {fmt_dist(dist(gaps_any))}")
    else:
        print("gaps between consecutive grants, ANY mode: n<2, no gaps")
    print()
    for mode in modes_target:
        seq = sorted([a for a in acq_target if a['mode'] == mode],
                     key=lambda a: a['realms'])
        if len(seq) >= 2:
            gaps = [seq[i + 1]['realms'] - seq[i]['realms']
                    for i in range(len(seq) - 1)]
            print(f"gaps between consecutive mode={mode} grants "
                  f"(n_grants={len(seq)}): {fmt_dist(dist(gaps))}")
        else:
            print(f"gaps between consecutive mode={mode} grants: "
                  f"n_grants={len(seq)}, insufficient for gaps")

    # ---- section d ----
    print()
    print(f"--- (d) per-node grant sequence and inter-grant period, ino={TARGET_INO} ---")
    for node in all_nodes:
        seq = sorted([a for a in acq_target if a['node'] == node],
                     key=lambda a: a['realms'])
        if not seq:
            print(f"{node}: 0 grants")
            continue
        t0n = seq[0]['realms']
        modes_str = ",".join(f"{a['mode']}@{a['realms']-t0n}ms" for a in seq)
        print(f"{node}: {len(seq)} grants, sequence (mode@t_rel_ms): {modes_str}")
        for mode in sorted(set(a['mode'] for a in seq)):
            sub = [a for a in seq if a['mode'] == mode]
            if len(sub) >= 2:
                periods = [sub[i + 1]['realms'] - sub[i]['realms']
                           for i in range(len(sub) - 1)]
                print(f"    mode={mode} inter-grant period: {fmt_dist(dist(periods))}")
            else:
                print(f"    mode={mode}: n_grants={len(sub)}, insufficient for period")

    # ---- section e ----
    print()
    print(f"--- (e) P138-BAST distributions, ino={TARGET_INO} ---")
    print(f"count per node (of {len(bast_target)} total):")
    for node in all_nodes:
        c = sum(1 for b in bast_target if b['node'] == node)
        print(f"  {node}: {c}")
    print()
    print(f"dur_us: {fmt_dist(dist([b['dur_us'] for b in bast_target]))}")
    for field in ('sa', 'sb', 'b1', 'b2', 'sc', 'sd', 'su', 'sw', 'sx'):
        vals = [b[field] for b in bast_target]
        print(f"{field}: {fmt_dist5(dist(vals))}")

    # ---- section f ----
    print()
    print("--- (f) BAST-to-next-grant handoff dead time, ino=%d ---" % TARGET_INO)
    acq_sorted_full = sorted(acq_target, key=lambda a: a['realms'])
    bast_sorted = sorted(bast_target, key=lambda b: b['realns'])
    handoff_other = []
    same_node_first = 0
    other_node_first = 0
    no_next_grant = 0
    for b in bast_sorted:
        bast_end_ms = b['realns'] / 1e6
        # next grant chronologically after this BAST, any node
        next_any = None
        for a in acq_sorted_full:
            if a['realms'] >= bast_end_ms:
                next_any = a
                break
        if next_any is None:
            no_next_grant += 1
            continue
        if next_any['node'] == b['node']:
            same_node_first += 1
        else:
            other_node_first += 1
        # next grant on a DIFFERENT node
        next_other = None
        for a in acq_sorted_full:
            if a['realms'] >= bast_end_ms and a['node'] != b['node']:
                next_other = a
                break
        if next_other is not None:
            handoff_other.append(next_other['realms'] - bast_end_ms)
    print(f"BASTs analyzed: {len(bast_sorted)}  "
          f"(no subsequent target-ino grant found for {no_next_grant})")
    print(f"handoff dead time to next grant on ANY OTHER node: "
          f"{fmt_dist(dist(handoff_other))}")
    print(f"BASTs immediately followed by a grant on the SAME node "
          f"(before any other node): {same_node_first} of "
          f"{same_node_first + other_node_first}")
    print(f"BASTs immediately followed by a grant on a DIFFERENT node: "
          f"{other_node_first} of {same_node_first + other_node_first}")

    # ---- section g ----
    print()
    print("--- (g) malformed / unparsed lines ---")
    print(f"malformed P138-ACQ/P138-BAST lines (grep-matched, regex failed): "
          f"{malformed}")
    print(f"other lines matched by grep but out of scope for this report "
          f"(P138-ACQSUM / mxfs-CCph rank=): {other_lines}")
    total_lines = len(acq_all) + len(bast_all) + malformed + other_lines
    print(f"total input lines across {len(logfiles)} node files: {total_lines}")


if __name__ == '__main__':
    main()
