#!/usr/bin/env python3
"""Aggregate P291-EXWIN exclusive-grant records collected from all nodes.

Input: a directory of node<N>.txt files, each containing that node's
`dmesg | grep P291-EXWIN` output followed by an optional
`--PROGRESS--` section with the dlm_fairness per-round trace.

Output:
  - hot-inode identification (most EX grants fleet-wide)
  - per-slot (winner) grant counts on the hot inode, split by path
  - the merged grant timeline on the hot inode sorted by realms
  - per-node first-grant time vs test start, and inter-grant gap stats

Usage: p291_aggregate.py <collect_dir> [--ino N] [--timeline]
"""
import sys, re, os, glob, statistics

# yt and wex are hex bitmasks (printed %llx, no 0x prefix)
LINE = re.compile(
    r'P291-EXWIN ino=(\d+) path=(\S+) mode=(\d+) slot=(\d+) '
    r'waited_ms=(\d+) yt=([0-9a-fA-F]+) wex=([0-9a-fA-F]+) realms=(\d+)')


def parse(d):
    recs = []
    prog = {}   # node -> [(ts, label)]
    for f in sorted(glob.glob(os.path.join(d, 'node*.txt'))):
        node = int(re.search(r'node(\d+)', f).group(1))
        in_prog = False
        for ln in open(f, errors='replace'):
            if ln.startswith('--PROGRESS--'):
                in_prog = True
                continue
            if in_prog:
                parts = ln.split()
                if len(parts) >= 2:
                    try:
                        prog.setdefault(node, []).append((float(parts[0]), ' '.join(parts[1:])))
                    except ValueError:
                        pass
                continue
            m = LINE.search(ln)
            if m:
                ino, path, mode, slot, waited, yt, wex, realms = m.groups()
                recs.append(dict(node=node, ino=int(ino), path=path,
                                 mode=int(mode), slot=int(slot),
                                 waited_ms=int(waited), yt=int(yt, 16),
                                 wex=int(wex, 16), realms=int(realms)))
    return recs, prog


def main():
    d = sys.argv[1]
    want_timeline = '--timeline' in sys.argv
    ino_arg = None
    if '--ino' in sys.argv:
        ino_arg = int(sys.argv[sys.argv.index('--ino') + 1])
    recs, prog = parse(d)
    print(f'total records: {len(recs)} from {len(set(r["node"] for r in recs))} nodes')

    # Test window: earliest rounds_start across nodes
    starts = [ts for evs in prog.values() for ts, lab in evs if lab.startswith('rounds_start')]
    t0 = min(starts) if starts else None
    tend = max((ts for evs in prog.values() for ts, lab in evs), default=None)
    if t0:
        print(f'test window: rounds_start(min)={t0:.3f} last_progress={tend:.3f}')

    by_ino = {}
    for r in recs:
        # local grants only for hot-ino counting (mint/nom are release-side
        # observations of some winner and would double-count)
        if r['path'] in ('mint', 'nom'):
            continue
        if t0 and r['realms'] / 1000.0 < t0 - 2:
            continue
        by_ino.setdefault(r['ino'], []).append(r)
    top = sorted(by_ino.items(), key=lambda kv: -len(kv[1]))[:5]
    print('top inodes by in-window local EX grants:',
          [(i, len(v)) for i, v in top])
    hot = ino_arg if ino_arg is not None else (top[0][0] if top else None)
    if hot is None:
        return
    print(f'hot ino: {hot}')

    grants = sorted((r for r in recs if r['ino'] == hot
                     and r['path'] not in ('mint', 'nom')
                     and (not t0 or r['realms'] / 1000.0 >= t0 - 2)),
                    key=lambda r: r['realms'])
    # per-node counts + first grant time
    per_node = {}
    for g in grants:
        per_node.setdefault(g['node'], []).append(g)
    print(f'\nper-node grant counts on ino {hot} (in-window): '
          f'{len(per_node)} nodes granted')
    rows = []
    for n, gs in per_node.items():
        first = gs[0]['realms'] / 1000.0 - (t0 or 0)
        paths = {}
        for g in gs:
            paths[g['path']] = paths.get(g['path'], 0) + 1
        rows.append((n, len(gs), first, paths))
    rows.sort(key=lambda r: r[2])
    print(f'{"node":>5} {"grants":>6} {"first_s":>8}  paths')
    for n, c, first, paths in rows:
        print(f'{n:>5} {c:>6} {first:>8.2f}  {paths}')
    missing = sorted(set(range(1, 33)) - set(per_node))
    if missing:
        print('nodes with ZERO in-window grants:', missing)

    # inter-grant gaps (handoff cadence)
    if len(grants) > 1:
        gaps = [(b['realms'] - a['realms']) for a, b in zip(grants, grants[1:])]
        print(f'\ninter-grant gap ms on ino {hot}: n={len(gaps)} '
              f'median={statistics.median(gaps):.0f} mean={statistics.mean(gaps):.0f} '
              f'p90={sorted(gaps)[int(len(gaps)*0.9)]} max={max(gaps)}')
        # repeat-win runs: how often does the same node win twice in a row
        runs = sum(1 for a, b in zip(grants, grants[1:]) if a['node'] == b['node'])
        print(f'consecutive same-node wins: {runs}/{len(gaps)}')

    if want_timeline:
        print(f'\ntimeline on ino {hot} (rel_s node path waited_ms slot yt wex):')
        for g in grants:
            rel = g['realms'] / 1000.0 - (t0 or 0)
            print(f'{rel:8.3f} n{g["node"]:<3} {g["path"]:<8} '
                  f'w={g["waited_ms"]:<6} slot={g["slot"]:<3} '
                  f'yt={g["yt"]:x} wex={g["wex"]:x}')

    # per-node round completion from progress traces
    print('\nper-node rounds completed (from progress traces):')
    comp = []
    for n in sorted(prog):
        evs = prog[n]
        rlabels = [lab for ts, lab in evs if re.match(r'r=\d+', lab)]
        last_r = max((int(lab.split('=')[1]) for lab in rlabels), default=0)
        tlast = max((ts for ts, lab in evs if re.match(r'r=\d+', lab)), default=None)
        comp.append((n, last_r, (tlast - t0) if (tlast and t0) else None))
    comp.sort(key=lambda x: -x[1])
    for n, r, tl in comp:
        print(f'  node{n:<3} rounds={r:<3} last_at={tl:.2f}s' if tl is not None
              else f'  node{n:<3} rounds={r}')


if __name__ == '__main__':
    main()
