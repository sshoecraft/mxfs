#!/usr/bin/env python3
"""handoff_anatomy.py <evidence_dir> — report for tests/handoff_anatomy.sh.

Reads test*.log (journalctl -o short-precise lines, all P-probes), ino.txt,
slot.txt, w.<n> (per-LBA watch counters) and op.<n> (per-node walls) and prints:

  (a) hot-slot command load per create (reads / CAWs / miscompares), with the
      P383-SLOTREAD caller census (which code path issued each read);
  (b) the holder-side release decomposition for the target ino (P138-BAST
      stages sa sb b1 b2 sc sd su sw sx), p50/p90/mean;
  (c) unlock contention (P381-UNLK-CONTEND): share of unlocks that lost >=1
      CAS, miscompares, nap ms, and the classifier histogram;
  (d) wake policy (P382-WAKE kind mint/ticket/field, woken vs waiters);
  (e) adopt cost (P6H-ADOPT elapsed_ms, reads) and P63-HANDOFF / P26-REBUILD
      counts;
  (f) acquire waits (P138-WAIT / P139-LOCKTOTAL) by mode;
  (g) the per-hop TIMELINE: every EX release (P138-BAST realns) paired with
      the next EX grant on another node (P138-ACQ realms - elapsed_ms is the
      acquire start, realms the grant) -> transfer gap, and the following
      tenure length (grant -> that node's next release start).

Every number is a lower bound where the probe is capped (P138-ACQ 4000/boot,
P138-BAST ratelimited, P381/P382 20000, P6H-ADOPT capped).
"""
import glob
import os
import re
import statistics
import sys

R = {
    'bast': re.compile(r'mxfs: P138-BAST ino=(\d+) dur_us=(\d+) dir=(-?\d+) clean=(-?\d+) sa=(\d+) sb=(\d+) b1=(\d+) b2=(\d+) sc=(\d+) sd=(\d+) su=(\d+) sw=(\d+) sx=(\d+) realns=(\d+)'),
    'acq': re.compile(r'mxfs: P138-ACQ type=(\d+) ino=(\d+) ag=(\d+) mode=(\d+) elapsed_ms=(\d+) rc=(-?\d+) realms=(\d+)'),
    'wait': re.compile(r'mxfs: P138-WAIT ino=(\d+) mode=(\d+) elapsed_ms=(\d+) ffw_ms=(\d+) ytd=(\d+) poll=(\d+) caw_try=(\d+) caw_miss=(\d+) caw_err=(\d+) caw_svc_ms=(\d+) reads=(\d+) realms=(\d+)'),
    'lt': re.compile(r'mxfs: P139-LOCKTOTAL ino=(\d+) req=(\d+) rc=(-?\d+) total_ms=(\d+) retries=(\d+)'),
    'unlk': re.compile(r'mxfs: P381-UNLK-CONTEND ino=(\d+) retries=(\d+) miscmp=(\d+) sleep_ms=(\d+) wall_ms=(\d+) backoff=(\d+) benign=(\d+) contended=(\d+) fast=(\d+) fr=(-?\d+) ident=(\d+) multigen=(\d+) selfbits=(\d+) removed=(\d+) noreg=(\d+) holders=(\d+) yieldto=(\d+) control=(\d+)'),
    'wake': re.compile(r'mxfs: P382-WAKE ino=(\d+) kind=(\w+) woken=(\d+) waiters=(\d+) waiters_ex=(\d+) gm=(\d+)->(\d+)'),
    'adopt': re.compile(r'mxfs: P6H-ADOPT ino=(\d+) mode=(\d+) held=(\d+) elapsed_ms=(\d+) gen=(\d+) reg_gen=(\d+) handoff=(\d+) reads=(\d+)'),
    'slotread': re.compile(r'mxfs: P383-SLOTREAD slot=(\d+) rc=(-?\d+) caller=(\S+)'),
}


def pct(v, p):
    if not v:
        return 0
    s = sorted(v)
    return s[min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1))))]


def dist(name, v, unit=''):
    if not v:
        return f"  {name:<12} n=0"
    return (f"  {name:<12} n={len(v):<6} p50={pct(v, 50):<9.1f} p90={pct(v, 90):<9.1f} "
            f"p99={pct(v, 99):<9.1f} mean={statistics.mean(v):<9.1f} max={max(v)}{unit}")


def main(d):
    ino = int(open(os.path.join(d, 'ino.txt')).read().strip())
    slot = open(os.path.join(d, 'slot.txt')).read().strip()
    files = sorted(glob.glob(os.path.join(d, 'test*.log')),
                   key=lambda f: int(re.search(r'test(\d+)\.log', f).group(1)))
    ev = {k: [] for k in R}
    nodes = 0
    for f in files:
        node = re.search(r'(test\d+)\.log', f).group(1)
        nodes += 1
        for line in open(f, errors='replace'):
            for k, rx in R.items():
                m = rx.search(line)
                if m:
                    ev[k].append((node,) + m.groups())
                    break
    creates = 0
    walls = []
    for f in glob.glob(os.path.join(d, 'op.*')):
        m = re.search(r'WALL (\d+)', open(f, errors='replace').read())
        if m:
            walls.append(int(m.group(1)))
    P = len(walls) or nodes
    F = 0
    # creates per node from the op files' file count is not recorded; take F from the sh arg via report caller env
    F = int(os.environ.get('HA_F', '0')) or 0
    print(f"=== handoff anatomy: ino={ino} slot={slot} nodes={nodes} walls n={len(walls)} "
          f"p50={pct(walls, 50)}ms max={max(walls) if walls else 0}ms ===")

    # (a) hot-slot load
    rd = sp = cw = mc = er = 0
    rdt = cwt = 0
    n = 0
    for f in glob.glob(os.path.join(d, 'w.*')):
        for line in open(f, errors='replace'):
            t = line.split()
            if len(t) == 9 and all(x.isdigit() for x in t):
                v = list(map(int, t))
                rd += v[0]; rdt += v[1]; sp += v[3]; cw += v[4]; cwt += v[5]; mc += v[7]; er += v[8]; n += 1
    ex_grants = sum(1 for e in ev['acq'] if int(e[2]) == ino and int(e[4]) == 5)
    denom = creates or ex_grants or 1
    print(f"\n--- (a) command load on slot {slot} ({n} nodes reporting); per-EX-grant denominators use P138-ACQ mode=5 count={ex_grants} (>5 ms acquires only)")
    print(f"  READ(16)+FUA {rd}  span reads {sp}  CAW {cw} (miscompare {mc} = {100.0 * mc / (cw or 1):.0f}%)  errors {er}")
    print(f"  per EX grant: reads {rd / denom:.1f}  CAWs {cw / denom:.2f}  landed {(cw - mc) / denom:.2f}")
    print(f"  summed service on the sector: reads {rdt / 1000.0:.1f}s  CAWs {cwt / 1000.0:.1f}s")
    callers = {}
    for e in ev['slotread']:
        if e[1] == slot:
            c = re.sub(r'\+0x[0-9a-f]+/0x[0-9a-f]+', '', e[3])
            callers[c] = callers.get(c, 0) + 1
    tot = sum(callers.values())
    print(f"  P383-SLOTREAD caller census: {tot} tagged reads")
    for c, k in sorted(callers.items(), key=lambda x: -x[1])[:12]:
        print(f"    {k:>7}  {100.0 * k / (tot or 1):5.1f}%  {c}")

    # (b) release decomposition
    b = [e for e in ev['bast'] if int(e[1]) == ino]
    print(f"\n--- (b) holder-side release, ino={ino}, P138-BAST n={len(b)} (dir={sum(1 for e in b if e[3]=='1')} clean={sum(1 for e in b if e[4]=='1')})")
    names = ['dur_us', 'sa', 'sb', 'b1', 'b2', 'sc', 'sd', 'su', 'sw', 'sx']
    idx = [2, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    for nm, i in zip(names, idx):
        print(dist(nm, [int(e[i]) for e in b], 'us'))

    # (c) unlock contention
    u = [e for e in ev['unlk'] if int(e[1]) == ino]
    print(f"\n--- (c) unlock contention P381-UNLK-CONTEND ino={ino}: contended unlocks {len(u)} of {len(b)} releases ({100.0 * len(u) / (len(b) or 1):.1f}%)")
    if u:
        print(dist('retries', [int(e[2]) for e in u]))
        print(dist('miscmp', [int(e[3]) for e in u]))
        print(dist('sleep_ms', [int(e[4]) for e in u], 'ms'))
        print(dist('wall_ms', [int(e[5]) for e in u], 'ms'))
        keys = ['benign', 'contended', 'fast', 'ident', 'multigen', 'selfbits', 'removed', 'noreg', 'holders', 'yieldto', 'control']
        ki = [7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18]
        print('  classifier sums: ' + ' '.join(f"{k}={sum(int(e[i]) for e in u)}" for k, i in zip(keys, ki)))

    # (d) wake policy
    w = [e for e in ev['wake'] if int(e[1]) == ino]
    print(f"\n--- (d) wake policy P382-WAKE ino={ino}: n={len(w)}")
    for kind in ('mint', 'ticket', 'field'):
        k = [e for e in w if e[2] == kind]
        if k:
            print(f"  {kind:<7} n={len(k):<6} {100.0 * len(k) / len(w):5.1f}%  woken mean={statistics.mean(int(e[3]) for e in k):.2f}  waiters mean={statistics.mean(int(e[4]) for e in k):.2f}  waiters_ex mean={statistics.mean(int(e[5]) for e in k):.2f}")

    # (e) adopt / handoff / rebuild
    a = [e for e in ev['adopt'] if int(e[1]) == ino]
    print(f"\n--- (e) adopt P6H-ADOPT ino={ino}: n={len(a)}  P63-HANDOFF={sum(1 for f in files for l in open(f, errors='replace') if f'P63-HANDOFF ino={ino} ' in l)}  P26-REBUILD-OK={sum(1 for f in files for l in open(f, errors='replace') if f'P26-REBUILD-OK ino={ino} ' in l)}")
    for mode in sorted(set(e[2] for e in a)):
        k = [e for e in a if e[2] == mode]
        print(f"  mode={mode} " + dist('elapsed_ms', [int(e[4]) for e in k], 'ms').strip())
        print(f"  mode={mode} " + dist('reads', [int(e[8]) for e in k]).strip())

    # (f) waits
    wt = [e for e in ev['wait'] if int(e[1]) == ino]
    print(f"\n--- (f) acquire waits P138-WAIT ino={ino}: n={len(wt)} (>5 ms waits only)")
    for mode in sorted(set(e[2] for e in wt)):
        k = [e for e in wt if e[2] == mode]
        print(f"  mode={mode} " + dist('elapsed_ms', [int(e[3]) for e in k], 'ms').strip())
        print(f"  mode={mode} " + dist('ffw_ms', [int(e[4]) for e in k], 'ms').strip())
        print(f"  mode={mode} " + dist('reads', [int(e[11]) for e in k]).strip())
        print(f"  mode={mode} " + dist('caw_try', [int(e[7]) for e in k]).strip() + f"  caw_miss sum={sum(int(e[8]) for e in k)}")
    lt = [e for e in ev['lt'] if int(e[1]) == ino]
    print(f"  P139-LOCKTOTAL ino={ino}: n={len(lt)} " + dist('total_ms', [int(e[4]) for e in lt], 'ms').strip() + f"  retries sum={sum(int(e[5]) for e in lt)}")
    acq = [e for e in ev['acq'] if int(e[2]) == ino]
    for mode in sorted(set(e[4] for e in acq)):
        k = [e for e in acq if e[4] == mode]
        print(f"  P138-ACQ mode={mode} " + dist('elapsed_ms', [int(e[5]) for e in k], 'ms').strip())

    # (g) per-hop timeline: EX release end -> next EX grant elsewhere
    rel = sorted(((int(e[14]) / 1e6, e[0], int(e[2]) / 1000.0) for e in b), key=lambda x: x[0])  # (ms, node, dur_ms)
    gr = sorted(((int(e[7]), e[0], int(e[5])) for e in acq if e[4] == '5'), key=lambda x: x[0])  # (grant ms, node, elapsed)
    transfer, tenure = [], []
    j = 0
    for t_rel, node, dur in rel:
        while j < len(gr) and gr[j][0] < t_rel:
            j += 1
        k = j
        while k < len(gr) and gr[k][1] == node:
            k += 1
        if k < len(gr):
            gap = gr[k][0] - t_rel
            if 0 <= gap < 5000:
                transfer.append(gap)
                # tenure of the grantee: next release START on that node after the grant
                nxt = [r for r in rel if r[1] == gr[k][1] and r[0] - r[2] >= gr[k][0]]
                if nxt:
                    tenure.append(nxt[0][0] - nxt[0][2] - gr[k][0])
    print(f"\n--- (g) per-hop timeline (EX release end -> next EX grant on another node; wall clocks across nodes, NTP skew applies)")
    print(dist('transfer_ms', transfer, 'ms'))
    print(dist('tenure_ms', tenure, 'ms'))
    print(dist('release_ms', [r[2] for r in rel], 'ms'))
    hops = len(transfer)
    if hops:
        print(f"  hop = release + transfer + tenure: p50 {pct([r[2] for r in rel], 50):.1f} + {pct(transfer, 50):.1f} + {pct(tenure, 50):.1f} ms  (hops paired={hops})")


if __name__ == '__main__':
    main(sys.argv[1])
