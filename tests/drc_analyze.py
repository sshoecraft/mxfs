#!/usr/bin/env python3
# drc_analyze.py — parse dir_reuse_coherency DRCph markers from both node logs
# and report per-round per-phase durations + the cross-node critical path.
# Usage: tests/drc_analyze.py tests/_cap/test1.log tests/_cap/test2.log
import sys, re

PH = re.compile(r'\[\s*([0-9.]+)\] mxfs-DRCph r=(\d+) rank=(\d+) PHASE=(\S+)')

def parse(path):
    # rank -> round -> phase -> ts
    d = {}
    rank = None
    for line in open(path, errors='replace'):
        m = PH.search(line)
        if not m:
            continue
        ts, rnd, rk, ph = float(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
        rank = rk
        d.setdefault(rnd, {})[ph] = ts
    return rank, d

def main():
    logs = sys.argv[1:3]
    nodes = []
    for p in logs:
        rk, d = parse(p)
        nodes.append((p, rk, d))
    # union of rounds
    allr = sorted(set().union(*[set(d.keys()) for _,_,d in nodes]))
    print(f"{'rnd':>3} | " + " | ".join(f"r{rk}: crt  vfy  rm   gap " for _,rk,_ in nodes) + " | span(crit)")
    prev_cs = {}
    totals = {}
    for r in allr:
        cells = []
        spans = []
        for p, rk, d in nodes:
            rr = d.get(r, {})
            cs = rr.get('create-start'); cd = rr.get('create-done')
            vd = rr.get('verify-done'); rd = rr.get('rm-done')
            crt = (cd-cs) if cs and cd else None
            vfy = (vd-cd) if cd and vd else None
            rm  = (rd-vd) if vd and rd else None
            # gap = this round's rm-done -> next round's create-start (same node)
            ncs = d.get(r+1, {}).get('create-start')
            gap = (ncs-rd) if rd and ncs else None
            def f(x): return f"{x:4.1f}" if x is not None else "  - "
            cells.append(f"{f(crt)} {f(vfy)} {f(rm)} {f(gap)}")
            for k,v in (('crt',crt),('vfy',vfy),('rm',rm),('gap',gap)):
                if v is not None:
                    totals.setdefault(rk,{}).setdefault(k,0.0)
                    totals[rk][k]+=v
            if cs and ncs:
                spans.append(ncs-cs)
        span = max(spans) if spans else None
        sstr = f"{span:5.1f}" if span is not None else "  -  "
        print(f"{r:>3} | " + " | ".join(cells) + f" | {sstr}")
    print("\n--- per-node totals (sum over all parsed rounds) ---")
    for _, rk, d in nodes:
        t = totals.get(rk, {})
        print(f"rank{rk}: create={t.get('crt',0):6.1f}  verify={t.get('vfy',0):6.1f}  "
              f"rm={t.get('rm',0):6.1f}  gap={t.get('gap',0):6.1f}  "
              f"rounds_parsed={len(d)}")
    # overall test wall from earliest create-start to latest rm-done across nodes
    mn=mx=None
    for _,_,d in nodes:
        for r,rr in d.items():
            for ph,ts in rr.items():
                mn = ts if mn is None else min(mn,ts)
                mx = ts if mx is None else max(mx,ts)
    if mn is not None:
        print(f"\noverall span (earliest marker -> latest marker): {mx-mn:.1f}s  [{mn:.1f}..{mx:.1f}]")

main()
