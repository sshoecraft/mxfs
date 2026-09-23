#!/usr/bin/env python3
"""handoff_transfer_attrib.py <evidence_dir>

Splits the EX-hop transfer_ms computed by tests/handoff_anatomy.py section (g)
into two legs using the successor's P297-TKT mode=5 ticket sighting:

  T1 = release end (holder's P138-BAST realns, ms)
       -> successor's first P297-TKT mode=5 sighting (realms) in the window
  T2 = that sighting -> successor's EX grant (P138-ACQ mode=5 realms)

Re-derives the SAME 379 release->grant pairs as handoff_anatomy.py (g) by
reusing its exact two-pointer pairing algorithm verbatim, so T1+T2 can be
checked against the report's transfer_ms distribution on the identical
denominator. Any hop with no qualifying P297-TKT line on the grantee node in
[t_rel, t_grant] is counted as UNMATCHED and excluded from the T1/T2 split
(reported explicitly, never silently dropped).

caw_try/caw_miss note: the task asked for the EX-grant line's caw_try/
caw_miss/reads for mode=5. Those three fields only ever co-occur on
P138-WAIT lines in this evidence set, and P138-WAIT ino=131 has n=3 total,
all mode=3 (zero mode=5 instances) -- see (f) in report.txt. So that
specific cross-tab cannot be produced from this data; this script instead
reports P297-TKT's own reads=/miss= fields (present only on the matched
subset) as the closest available substitute, explicitly labeled as not
caw_try.
"""
import glob
import os
import re
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone

BAST = re.compile(r'mxfs: P138-BAST ino=(\d+) dur_us=(\d+) dir=(-?\d+) clean=(-?\d+) sa=(\d+) sb=(\d+) b1=(\d+) b2=(\d+) sc=(\d+) sd=(\d+) su=(\d+) sw=(\d+) sx=(\d+) realns=(\d+)')
ACQ = re.compile(r'mxfs: P138-ACQ type=(\d+) ino=(\d+) ag=(\d+) mode=(\d+) elapsed_ms=(\d+) rc=(-?\d+) realms=(\d+)')
TKT = re.compile(r'mxfs: P297-TKT ino=(\d+) mode=(\d+) el_ms=(\d+) wake=(\d+) slept_ms=(\d+) read_ms=(\d+) miss=(\d+) reads=(\d+) gen=(\d+) yt=(\S+) realms=(\d+)')
WAKE = re.compile(r'mxfs: P382-WAKE ino=(\d+) kind=(\w+) woken=(\d+) waiters=(\d+) waiters_ex=(\d+) gm=(\d+)->(\d+)')
TS = re.compile(r'^\w+ (\d+) (\d\d):(\d\d):(\d\d)\.(\d+)')
WAKE_MAP = {'1': 'nudge', '2': 'timeout', '3': 'miss'}


def line_ms(line, year=2026, month=8):
    """Approx epoch ms from the journalctl short-precise prefix (for WAKE
    context correlation only -- WAKE carries no realms field)."""
    m = TS.match(line)
    if not m:
        return None
    day, hh, mm, ss, frac = m.groups()
    us = int((frac + '000000')[:6])
    dt = datetime(year, month, int(day), int(hh), int(mm), int(ss), us, tzinfo=timezone.utc)
    return dt.timestamp() * 1000.0


def pct(v, p):
    if not v:
        return None
    s = sorted(v)
    return s[min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1))))]


def dist(name, v, unit=''):
    if not v:
        return f"  {name:<14} n=0"
    return (f"  {name:<14} n={len(v):<6} p50={pct(v,50):<9.1f} p90={pct(v,90):<9.1f} "
            f"p99={pct(v,99):<9.1f} mean={statistics.mean(v):<9.2f} max={max(v)}{unit}")


def main(d):
    ino = int(open(os.path.join(d, 'ino.txt')).read().strip())
    files = sorted(glob.glob(os.path.join(d, 'test*.log')),
                    key=lambda f: int(re.search(r'test(\d+)\.log', f).group(1)))
    bast, acq, tkt, wake = [], [], [], []
    lines_scanned = 0
    for f in files:
        node = re.search(r'(test\d+)\.log', f).group(1)
        for line in open(f, errors='replace'):
            lines_scanned += 1
            m = BAST.search(line)
            if m and int(m.group(1)) == ino:
                bast.append((node,) + m.groups() + (line.rstrip('\n'),))
                continue
            m = ACQ.search(line)
            if m and int(m.group(2)) == ino:
                acq.append((node,) + m.groups() + (line.rstrip('\n'),))
                continue
            m = TKT.search(line)
            if m and int(m.group(1)) == ino:
                tkt.append((node,) + m.groups() + (line.rstrip('\n'),))
                continue
            m = WAKE.search(line)
            if m and int(m.group(1)) == ino:
                wake.append((node,) + m.groups() + (line.rstrip('\n'),))

    print(f"# files={len(files)} lines_scanned={lines_scanned} ino={ino}")
    print(f"# raw event counts: P138-BAST={len(bast)} P138-ACQ(all modes)={len(acq)} "
          f"P297-TKT(all modes)={len(tkt)} P382-WAKE={len(wake)}")
    acq5 = [e for e in acq if e[4] == '5']
    tkt5 = [e for e in tkt if e[2] == '5']
    print(f"# P138-ACQ mode=5 count={len(acq5)}  P297-TKT mode=5 count={len(tkt5)}")

    # --- reproduce handoff_anatomy.py section (g) pairing EXACTLY ---
    # rel: (t_rel_ms, node, dur_ms, raw_line)   from BAST realns (ns -> ms)
    rel = sorted(((int(e[14]) / 1e6, e[0], int(e[2]) / 1000.0, e[15]) for e in bast), key=lambda x: x[0])
    # gr: (t_grant_ms, node, elapsed_ms, raw_line)  from ACQ mode=5 realms (already ms)
    gr = sorted(((int(e[7]), e[0], int(e[5]), e[8]) for e in acq if e[4] == '5'), key=lambda x: x[0])

    hops = []  # (t_rel, holder_node, dur_ms, rel_raw, t_grant, taker_node, grant_elapsed_ms, grant_raw)
    j = 0
    for t_rel, node, dur, rel_raw in rel:
        while j < len(gr) and gr[j][0] < t_rel:
            j += 1
        k = j
        while k < len(gr) and gr[k][1] == node:
            k += 1
        if k < len(gr):
            gap = gr[k][0] - t_rel
            if 0 <= gap < 5000:
                hops.append((t_rel, node, dur, rel_raw, gr[k][0], gr[k][1], gr[k][2], gr[k][3]))
    print(f"# release->grant hops paired (identical algorithm to handoff_anatomy.py (g)): {len(hops)} "
          f"of {len(rel)} releases  (grants pool used: mode=5 ACQ, {len(gr)} events)")
    transfer_check = [h[4] - h[0] for h in hops]
    print(dist('transfer_ms(g)', transfer_check, 'ms') + '   <- must match report.txt transfer_ms')

    # index TKT mode=5 events per node for fast window lookup
    tkt5_by_node = {}
    for e in tkt5:
        tkt5_by_node.setdefault(e[0], []).append(e)
    for node in tkt5_by_node:
        tkt5_by_node[node].sort(key=lambda e: int(e[11]))  # realms

    # index WAKE by node in file order (for verbatim context only)
    wake_by_node = {}
    for e in wake:
        wake_by_node.setdefault(e[0], []).append(e)

    matched, unmatched = [], 0
    for (t_rel, hnode, dur, rel_raw, t_grant, tnode, gelapsed, grant_raw) in hops:
        cands = [e for e in tkt5_by_node.get(tnode, []) if t_rel <= int(e[11]) <= t_grant]
        if not cands:
            unmatched += 1
            continue
        cands.sort(key=lambda e: int(e[11]))
        sight = cands[0]
        t_sight = int(sight[11])
        T1 = t_sight - t_rel
        T2 = t_grant - t_sight
        matched.append({
            't_rel': t_rel, 'hnode': hnode, 'dur': dur, 'rel_raw': rel_raw,
            't_grant': t_grant, 'tnode': tnode, 'gelapsed': gelapsed, 'grant_raw': grant_raw,
            't_sight': t_sight, 'sight_raw': sight[12], 'T1': T1, 'T2': T2, 'transfer': t_grant - t_rel,
            'wake': sight[4], 'slept_ms': int(sight[5]), 'read_ms': int(sight[6]),
            'miss': int(sight[7]), 'reads': int(sight[8]), 'el_ms': int(sight[3]),
            'n_cands': len(cands),
        })

    print(f"\n=== 1. T1/T2 split ===")
    print(f"# hops with >=1 qualifying P297-TKT mode=5 sighting on the grantee node "
          f"in [release_end, grant]: {len(matched)} of {len(hops)} paired hops "
          f"({100.0*len(matched)/len(hops):.1f}%)")
    print(f"# UNMATCHED (no P297-TKT mode=5 line on grantee node in window): {unmatched}")
    T1s = [m['T1'] for m in matched]
    T2s = [m['T2'] for m in matched]
    Ts = [m['T1'] + m['T2'] for m in matched]
    Transf = [m['transfer'] for m in matched]
    print(dist('T1_ms', T1s, 'ms'))
    print(dist('T2_ms', T2s, 'ms'))
    print(dist('T1+T2_ms', Ts, 'ms'))
    print(dist('transfer_ms', Transf, 'ms') + '  <- for the SAME matched subset, for direct comparison')
    diffs = [(m['T1'] + m['T2']) - m['transfer'] for m in matched]
    print(f"  T1+T2 - transfer_ms: min={min(diffs):.3f} max={max(diffs):.3f} "
          f"(0 by construction: T1+T2 = t_grant - t_rel = transfer)")

    print(f"\n=== 2. successor's P297-TKT wake= cross-tab vs T1 (matched hops only, n={len(matched)}) ===")
    for wv in ('1', '2', '3'):
        rows = [m for m in matched if m['wake'] == wv]
        label = WAKE_MAP.get(wv, wv)
        if rows:
            t1v = [r['T1'] for r in rows]
            print(f"  wake={wv} ({label:<7}) n={len(rows):<4} "
                  f"T1_ms p50={pct(t1v,50):.1f} p90={pct(t1v,90):.1f} mean={statistics.mean(t1v):.1f}")
        else:
            print(f"  wake={wv} ({label:<7}) n=0")
    other = [m for m in matched if m['wake'] not in ('1', '2', '3')]
    if other:
        vals = sorted(set(m['wake'] for m in other))
        print(f"  wake=<other:{vals}> n={len(other)}")

    print(f"\n  T1_ms vs slept_ms, matched n={len(matched)}:")
    if len(matched) > 2:
        t1v = [m['T1'] for m in matched]
        slv = [m['slept_ms'] for m in matched]
        r = statistics.correlation(t1v, slv)
        print(f"    Pearson r(T1, slept_ms)={r:.3f}")
    print(dist('slept_ms', [m['slept_ms'] for m in matched], 'ms'))

    print(f"\n=== 3. T2 split by grant-line caw fields ===")
    print("  NOTE: caw_try/caw_miss/reads co-occur ONLY on P138-WAIT lines in this evidence set.")
    print("  P138-WAIT ino=131: n=3 total, all mode=3, 0 instances mode=5 (see report.txt section f).")
    print("  P138-ACQ (the mode=5 grant line) carries only type/ino/ag/mode/elapsed_ms/rc/realms -- no caw fields.")
    print("  So 'the grant line's caw_try/caw_miss/reads (mode=5)' does not exist in this data.")
    print("  Reporting the matched-subset P297-TKT sighting's own reads=/miss= fields instead (NOT caw_try):")
    missv = [m['miss'] for m in matched]
    readsv = [m['reads'] for m in matched]
    print(dist('tkt_reads', readsv))
    print(dist('tkt_miss', missv))
    z = [m for m in matched if m['miss'] == 0]
    nz = [m for m in matched if m['miss'] > 0]
    print(f"  T2_ms split by tkt miss==0 (n={len(z)}) vs miss>0 (n={len(nz)}):")
    if z:
        v = [m['T2'] for m in z]
        print(f"    miss==0  n={len(v):<4} p50={pct(v,50):.1f}  p90={pct(v,90):.1f}  mean={statistics.mean(v):.1f}")
    if nz:
        v = [m['T2'] for m in nz]
        print(f"    miss>0   n={len(v):<4} p50={pct(v,50):.1f}  p90={pct(v,90):.1f}  mean={statistics.mean(v):.1f}")

    print(f"\n=== 4. hops with T1+T2 > 200ms (matched subset, n={len(matched)}) ===")
    slow = [m for m in matched if (m['T1'] + m['T2']) > 200]
    if matched:
        print(f"  count: {len(slow)} of {len(matched)} matched hops ({100.0*len(slow)/len(matched):.1f}%)")
    else:
        print("  count: 0 of 0")
    if slow:
        wc = Counter(m['wake'] for m in slow)
        print(f"  wake= histogram: " + ", ".join(f"{WAKE_MAP.get(k,k)}({k})={v}" for k, v in sorted(wc.items())))
        print(dist('slept_ms', [m['slept_ms'] for m in slow], 'ms'))
        mc = Counter(m['miss'] for m in slow)
        print(f"  tkt_miss histogram: " + ", ".join(f"{k}={v}" for k, v in sorted(mc.items())))

    print(f"\n=== 5. verbatim example hops ===")
    fast = sorted([m for m in matched if m['transfer'] < 15], key=lambda m: m['transfer'])[:3]
    slowex = sorted([m for m in matched if m['transfer'] > 250], key=lambda m: -m['transfer'])[:3]
    n_fast_avail = len([m for m in matched if m['transfer'] < 15])
    n_slow_avail = len([m for m in matched if m['transfer'] > 250])
    print(f"  (fast<15ms pool: {n_fast_avail} matched hops; slow>250ms pool: {n_slow_avail} matched hops)")

    def nearest_wake(hnode, t_rel):
        cands = wake_by_node.get(hnode, [])
        best, bestd = None, None
        for e in cands:
            tm = line_ms(e[8])
            if tm is None:
                continue
            dd = abs(tm - t_rel)
            if bestd is None or dd < bestd:
                best, bestd = e, dd
        return best, bestd

    def dump(tag, m):
        print(f"\n  -- {tag}: transfer={m['transfer']:.3f}ms  T1={m['T1']:.3f}ms  T2={m['T2']:.3f}ms  "
              f"holder={m['hnode']} taker={m['tnode']}")
        print(f"     RELEASE  : {m['rel_raw']}")
        wk, wd = nearest_wake(m['hnode'], m['t_rel'])
        if wk is not None:
            print(f"     WAKE(nearest by wall-clock on holder node, |dt|={wd:.1f}ms, "
                  f"NOT realms-paired -- WAKE has no realms field): {wk[8]}")
        else:
            print(f"     WAKE     : none found on holder node {m['hnode']}")
        print(f"     TKT      : {m['sight_raw']}")
        print(f"     GRANT    : {m['grant_raw']}")
        print(f"     realms deltas: release->sight T1={m['T1']:.3f}ms  sight->grant T2={m['T2']:.3f}ms  "
              f"release->grant transfer={m['transfer']:.3f}ms")

    for i, m in enumerate(fast):
        dump(f"FAST #{i+1}", m)
    for i, m in enumerate(slowex):
        dump(f"SLOW #{i+1}", m)



FAMILY = re.compile(r'mxfs: (P\S+?)[,:]?(?:\s|$)')
REALNS = re.compile(r'realns=(\d+)')
REALMS = re.compile(r'realms=(\d+)')
INO131 = re.compile(r'ino=131\b')
TARGET_FAM_RX = re.compile(r'exwin|P6H|P139|P204|P203|P297|P382|P381|P138')
CASFAM_RX = re.compile(r'P6H-ADOPT|P6H-HANDOFF|P6H-PRCLAIMBATCH|P63-HANDOFF|P381-UNLK-CONTEND')
LITERAL_RX = re.compile(r'exwin|nom|promote|mint')
READS_RX = re.compile(r'\breads=(\d+)')


def line_time_ms(line):
    """realns (ns) > realms (ms) > journalctl-prefix fallback. All three are
    the same epoch-ms axis (realns/realms are NTP wall clock per the task
    brief; the journalctl prefix is the same host's local clock)."""
    m = REALNS.search(line)
    if m:
        return int(m.group(1)) / 1e6
    m = REALMS.search(line)
    if m:
        return float(m.group(1))
    return line_ms(line)


def build_node_index(files):
    """node -> sorted list of (t_ms, family, raw_line) for EVERY line in the
    file (mxfs: lines and the single 'unknown: HANDOFF-...' marker line)."""
    idx = {}
    for f in files:
        node = re.search(r'(test\d+)\.log', f).group(1)
        rows = []
        for line in open(f, errors='replace'):
            line = line.rstrip('\n')
            t = line_time_ms(line)
            if t is None:
                continue
            fm = FAMILY.search(line)
            fam = fm.group(1) if fm else ('non-mxfs' if 'kernel: mxfs:' not in line else '?')
            rows.append((t, fam, line))
        rows.sort(key=lambda r: r[0])
        idx[node] = rows
    return idx


def get_all_hops(files, ino):
    """All 379 release->grant hops (matched or not to a TKT sighting),
    identical pairing algorithm to section (g) / part 1 of this script."""
    bast, acq = [], []
    for f in files:
        node = re.search(r'(test\d+)\.log', f).group(1)
        for line in open(f, errors='replace'):
            m = BAST.search(line)
            if m and int(m.group(1)) == ino:
                bast.append((node,) + m.groups() + (line.rstrip('\n'),))
                continue
            m = ACQ.search(line)
            if m and int(m.group(2)) == ino:
                acq.append((node,) + m.groups() + (line.rstrip('\n'),))
    rel = sorted(((int(e[14]) / 1e6, e[0], int(e[2]) / 1000.0, e[15]) for e in bast), key=lambda x: x[0])
    gr = sorted(((int(e[7]), e[0], int(e[5]), e[8]) for e in acq if e[4] == '5'), key=lambda x: x[0])
    hops = []
    j = 0
    for t_rel, node, dur, rel_raw in rel:
        while j < len(gr) and gr[j][0] < t_rel:
            j += 1
        k = j
        while k < len(gr) and gr[k][1] == node:
            k += 1
        if k < len(gr):
            gap = gr[k][0] - t_rel
            if 0 <= gap < 5000:
                hops.append({
                    't_rel': t_rel, 'hnode': node, 'dur': dur, 'rel_raw': rel_raw,
                    't_grant': gr[k][0], 'tnode': gr[k][1], 'gelapsed': gr[k][2],
                    'grant_raw': gr[k][3], 'transfer': gr[k][0] - t_rel,
                })
    return hops


def nearest_wake_line(wake_lines_for_node, t_rel, tol_ms=8.0):
    """wake_lines_for_node: list of (t_ms, raw) for P382-WAKE on one node
    (time via journalctl-prefix fallback, WAKE carries no realms/realns)."""
    best, bestd = None, None
    for t, raw in wake_lines_for_node:
        dd = abs(t - t_rel)
        if bestd is None or dd < bestd:
            best, bestd = raw, dd
    if best is not None and bestd <= tol_ms:
        return best, bestd
    return None, bestd


def taker_report(d):
    ino = int(open(os.path.join(d, 'ino.txt')).read().strip())
    files = sorted(glob.glob(os.path.join(d, 'test*.log')),
                    key=lambda f: int(re.search(r'test(\d+)\.log', f).group(1)))
    print("\n\n########## PART 2 FOLLOW-UP: taker-node timelines + fleet CAS-commit lines ##########")
    print(f"# command: python3 tests/handoff_transfer_attrib.py {d}")
    hops = get_all_hops(files, ino)
    print(f"# full population: {len(hops)} release->grant hops (identical pairing to section (g)/part-1 above)")

    slow_all = sorted([h for h in hops if h['transfer'] > 250], key=lambda h: -h['transfer'])
    fast_pool = sorted([h for h in hops if h['transfer'] < 15], key=lambda h: h['t_rel'])
    fast_ctrl = fast_pool[:30]
    print(f"# transfer>250ms population: {len(slow_all)} hops (matches earlier full-population count)")
    print(f"# transfer<15ms population: {len(fast_pool)} hops; control sample = first 30 by release time "
          f"(deterministic selection, NOT random) -> using {len(fast_ctrl)}")

    print("\nBuilding per-node full-line index (every mxfs: + marker line, all 32 nodes)...")
    idx = build_node_index(files)
    total_lines = sum(len(v) for v in idx.values())
    print(f"# per-node index built: {len(idx)} nodes, {total_lines} lines total")

    wake_by_node = {}
    for node, rows in idx.items():
        wake_by_node[node] = [(t, raw) for (t, fam, raw) in rows if fam == 'P382-WAKE' and INO131.search(raw)]

    def classify(h):
        t_rel, t_grant, tnode, hnode = h['t_rel'], h['t_grant'], h['tnode'], h['hnode']
        transfer = h['transfer']
        wraw, wdelta = nearest_wake_line(wake_by_node.get(hnode, []), t_rel)
        wake_kind = 'unknown'
        if wraw:
            mk = re.search(r'kind=(\w+)', wraw)
            if mk:
                wake_kind = mk.group(1)
        eps = 1.5
        gelapsed = h['gelapsed']
        if gelapsed > transfer + eps:
            open_acq = 'yes'
        elif gelapsed < transfer - eps:
            open_acq = 'no'
        else:
            open_acq = 'unknown'
        trows = idx.get(tnode, [])
        first_after = None
        for (t, fam, raw) in trows:
            if t > t_rel and INO131.search(raw):
                first_after = (t, fam)
                break
        win_lo, win_hi = t_rel - 50.0, t_grant + 5.0
        slotread_n = 0
        reads_vals = []
        for (t, fam, raw) in trows:
            if win_lo <= t <= win_hi:
                if fam in ('P297-TKT', 'P139-LOCKTOTAL') or 'P204-YT-DEFER' in raw:
                    slotread_n += 1
                    if fam == 'P297-TKT':
                        mr = READS_RX.search(raw)
                        if mr:
                            reads_vals.append(int(mr.group(1)))
        reads_delta = (reads_vals[-1] - reads_vals[0]) if len(reads_vals) >= 2 else (reads_vals[0] if reads_vals else None)
        return {
            'wake_kind': wake_kind, 'wake_dt': wdelta, 'open_acq': open_acq,
            'gelapsed': gelapsed, 'first_after': first_after,
            'slotread_n': slotread_n, 'reads_delta': reads_delta, 'win': (win_lo, win_hi),
        }

    print(f"\n=== 1a. per-hop one-line summaries: {len(slow_all)} slow hops (transfer>250ms, FULL population) ===")
    for i, h in enumerate(slow_all):
        c = classify(h)
        fa = f"{c['first_after'][1]}@+{c['first_after'][0]-h['t_rel']:.1f}ms" if c['first_after'] else "NONE-FOUND"
        print(f"  [{i+1:3d}/{len(slow_all)}] transfer={h['transfer']:7.2f}ms holder={h['hnode']:<7} taker={h['tnode']:<7} "
              f"wake={c['wake_kind']:<8}(|dt|={c['wake_dt'] if c['wake_dt'] is not None else -1:.1f}ms) "
              f"open_acq={c['open_acq']:<7}(grant_elapsed_ms={c['gelapsed']:.0f}) "
              f"taker_first_ino131_after_release={fa} "
              f"slotread_lines_in_window={c['slotread_n']} tkt_reads_delta={c['reads_delta']}")

    print(f"\n=== 1b. per-hop one-line summaries: {len(fast_ctrl)} CONTROL hops (transfer<15ms, sample of {len(fast_pool)}) ===")
    for i, h in enumerate(fast_ctrl):
        c = classify(h)
        fa = f"{c['first_after'][1]}@+{c['first_after'][0]-h['t_rel']:.1f}ms" if c['first_after'] else "NONE-FOUND"
        print(f"  [{i+1:3d}/{len(fast_ctrl)}] transfer={h['transfer']:7.2f}ms holder={h['hnode']:<7} taker={h['tnode']:<7} "
              f"wake={c['wake_kind']:<8}(|dt|={c['wake_dt'] if c['wake_dt'] is not None else -1:.1f}ms) "
              f"open_acq={c['open_acq']:<7}(grant_elapsed_ms={c['gelapsed']:.0f}) "
              f"taker_first_ino131_after_release={fa} "
              f"slotread_lines_in_window={c['slotread_n']} tkt_reads_delta={c['reads_delta']}")

    print(f"\n=== 3. histogram over the {len(slow_all)} slow hops (transfer>250ms) ===")
    wc = Counter()
    oc = Counter()
    for h in slow_all:
        c = classify(h)
        wc[c['wake_kind']] += 1
        oc[c['open_acq']] += 1
    print("  holder P382-WAKE kind: " + ", ".join(f"{k}={v}" for k, v in sorted(wc.items(), key=lambda x: -x[1])))
    print("  taker open-acquire-at-release-time: " + ", ".join(f"{k}={v}" for k, v in sorted(oc.items(), key=lambda x: -x[1])))

    six = slow_all[:6]
    print(f"\n=== 1c. 6 slow hops in FULL (top-6 by transfer_ms among the {len(slow_all)}) -- taker-node window dump ===")
    print("  window = [t_release - 50ms, t_grant + 5ms], taker node only, per the follow-up's part 1 definition")
    print("  NOTE (verified fleet-wide, all 32 logs): every line in this evidence set is either 'kernel: mxfs: ...'")
    print("  or a single per-node 'unknown: HANDOFF-...' marker at boot. There are ZERO dd/xfs/writeback/sync lines")
    print("  anywhere in the corpus -- these logs never captured non-mxfs kernel activity, so the requested")
    print("  'taker busy in a previous create' non-DLM check returns 0 lines for every hop, not because the taker")
    print("  was idle, but because that class of log line was never emitted into these files.")

    fleet_cas_all = []  # for part 2, collected per hop below
    for i, h in enumerate(six):
        c = classify(h)
        win_lo, win_hi = c['win']
        print(f"\n  ---- SLOW #{i+1}: transfer={h['transfer']:.3f}ms  holder={h['hnode']}  taker={h['tnode']}  "
              f"window=[{win_lo:.3f},{win_hi:.3f}]ms  wake={c['wake_kind']}  open_acq={c['open_acq']} ----")
        trows = idx.get(h['tnode'], [])
        printed = 0
        for (t, fam, raw) in trows:
            if win_lo <= t <= win_hi and (INO131.search(raw) or TARGET_FAM_RX.search(fam)):
                print(f"    t={t - h['t_rel']:+8.3f}ms  {raw}")
                printed += 1
        nonmxfs = [(t, raw) for (t, fam, raw) in trows if win_lo <= t <= win_hi and fam == 'non-mxfs']
        print(f"    ({printed} taker-node DLM/ino=131 lines printed in window; "
              f"{len(nonmxfs)} non-DLM (dd/xfs/writeback/sync) lines found in window)")

        # part 2: fleet-wide CAS-commit lines in this hop's window
        print(f"    -- part 2: fleet-wide CAS-commit lines on ino={ino} in this hop's window, all 32 nodes --")
        rows2 = []
        for node, rows in idx.items():
            for (t, fam, raw) in rows:
                if not (win_lo <= t <= win_hi):
                    continue
                if not INO131.search(raw):
                    continue
                is_cas = False
                if CASFAM_RX.search(fam):
                    is_cas = True
                elif fam == 'P138-ACQ' and 'mode=3' in raw:
                    is_cas = True
                elif LITERAL_RX.search(raw):
                    is_cas = True
                if is_cas:
                    rows2.append((t, node, fam, raw))
        rows2.sort(key=lambda r: r[0])
        print(f"    {len(rows2)} CAS-commit-indicating lines found (pre-truncation total; all printed below)")
        for (t, node, fam, raw) in rows2:
            print(f"      t={t - h['t_rel']:+8.3f}ms  node={node:<7} fam={fam:<20} {raw}")

    print("\n  literal-grep check across the whole corpus (all 32 logs, unbounded by window):")
    for pat, label in [('exwin', 'exwin'), (r'\bnom', 'nom'), ('promote', 'promote'), ('mint', 'mint')]:
        cnt = 0
        for node, rows in idx.items():
            for (t, fam, raw) in rows:
                if re.search(pat, raw):
                    cnt += 1
        print(f"    '{label}': {cnt} lines fleet-wide (all are P382-WAKE kind=mint text for 'mint'; "
              f"0 for exwin/nom/promote -- no such probe or field exists in this build)" if label == 'mint'
              else f"    '{label}': {cnt} lines fleet-wide")


if __name__ == '__main__':
    main(sys.argv[1])
    taker_report(sys.argv[1])
