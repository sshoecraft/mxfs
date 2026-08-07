#!/usr/bin/env python3
"""drc_phase_census.py — where does a dir_reuse_coherency ROUND actually go?

Unlike drc_analyze.py (2 logs, coarse create/verify/rm), this aggregates ALL
N nodes and splits the round into every phase the test marks, separating
  WORK  = time a node spends inside a phase, and
  SKEW  = time the fastest node waits at a barrier for the slowest.
That distinction decides whether the 32-node pace defect is filesystem cost
or cross-node spread, which need completely different fixes.

Phase order per round (dir_reuse_coherency.sh):
  create-start -> sync1-done -> wave1-done -> wave2-done -> create-done
  -> [barrier wr] wrbar-done -> presync-done -> dc-done -> dc-real-done
  -> ls-done -> lookups-done -> verify-done -> [barrier vr] -> rm-done

Usage: drc_phase_census.py <dir-of-per-node-logs>   (files named *test<N>*)
"""
import sys, re, os, glob, statistics

PH = re.compile(r'\[\s*([0-9.]+)\] mxfs-DRCph r=(\d+) rank=(\d+) PHASE=(\S+)')
ORDER = ['create-start', 'sync1-done', 'wave1-done', 'wave2-done',
         'create-done', 'wrbar-done', 'presync-done', 'dc-done',
         'dc-real-done', 'ls-done', 'lookups-done', 'verify-done', 'rm-done']

def parse(path):
    d, rank = {}, None
    for line in open(path, errors='replace'):
        m = PH.search(line)
        if m:
            ts, rnd, rk, ph = float(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
            rank = rk
            d.setdefault(rnd, {})[ph] = ts
    return rank, d

def main():
    if len(sys.argv) < 2:
        print(__doc__); return 2
    nodes = []
    for p in sorted(glob.glob(os.path.join(sys.argv[1], '*'))):
        if not os.path.isfile(p):
            continue
        rk, d = parse(p)
        if rk is not None and d:
            nodes.append((os.path.basename(p), rk, d))
    if not nodes:
        print("no DRCph markers found"); return 1
    print(f"nodes with markers: {len(nodes)}")

    rounds = sorted(set().union(*[set(d.keys()) for _, _, d in nodes]))
    # Clocks are per-node monotonic (uptime) and NOT comparable across nodes.
    # Everything below is therefore computed per node and then aggregated.
    seg_tot, seg_max = {}, {}
    round_walls = []
    for r in rounds:
        walls = []
        for _, rk, d in nodes:
            rr = d.get(r, {})
            for a, b in zip(ORDER, ORDER[1:]):
                if a in rr and b in rr:
                    dt = rr[b] - rr[a]
                    if dt >= 0:
                        seg_tot.setdefault(f"{a}->{b}", []).append(dt)
            cs, rd = rr.get('create-start'), rr.get('rm-done')
            if cs and rd and rd > cs:
                walls.append(rd - cs)
        if walls:
            round_walls.append((r, min(walls), statistics.median(walls), max(walls)))

    print("\n--- per-round wall (create-start -> rm-done), across nodes ---")
    print(f"{'rnd':>3} {'min':>7} {'median':>7} {'max':>7} {'spread':>7}")
    for r, lo, md, hi in round_walls:
        print(f"{r:>3} {lo:7.2f} {md:7.2f} {hi:7.2f} {hi-lo:7.2f}")
    if round_walls:
        meds = [m for _, _, m in [(a, b, c) for a, b, c, _ in round_walls]]
        print(f"\nmedian round wall across rounds: {statistics.median(meds):.2f}s")

    print("\n--- phase segments: seconds per round, aggregated over all nodes/rounds ---")
    print(f"{'segment':<28} {'n':>5} {'median':>8} {'p90':>8} {'max':>8} {'share%':>7}")
    total_med = sum(statistics.median(v) for v in seg_tot.values()) or 1.0
    rows = []
    for a, b in zip(ORDER, ORDER[1:]):
        k = f"{a}->{b}"
        v = seg_tot.get(k)
        if not v:
            continue
        v2 = sorted(v)
        med = statistics.median(v2)
        p90 = v2[int(len(v2) * 0.9) - 1] if len(v2) > 1 else v2[0]
        rows.append((k, len(v2), med, p90, max(v2), 100.0 * med / total_med))
    for k, n, med, p90, mx, share in rows:
        print(f"{k:<28} {n:>5} {med:8.3f} {p90:8.3f} {mx:8.3f} {share:6.1f}%")

    print("\n--- interpretation ---")
    if rows:
        worst = max(rows, key=lambda x: x[2])
        print(f"dominant segment: {worst[0]} at {worst[2]:.2f}s median ({worst[5]:.0f}% of round)")
        spread = [hi - lo for _, lo, _, hi in round_walls]
        if spread:
            print(f"cross-node wall spread: median {statistics.median(spread):.2f}s, max {max(spread):.2f}s")
            print("  (large spread => barrier SKEW dominates: the round costs what the SLOWEST node costs;")
            print("   small spread with a large dominant segment => that segment is a real per-node FS cost)")
    return 0

if __name__ == '__main__':
    sys.exit(main())
