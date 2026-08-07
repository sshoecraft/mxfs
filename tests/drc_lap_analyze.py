#!/usr/bin/env python3
"""drc_lap_analyze.py — diff drc_lap_probe.sh snapshots across a lap.

Usage: tests/drc_lap_analyze.py <tagA> <tagB> [outdir]
Prints per-node deltas of the interesting /proc/fs/mxfs/stat counters
(log line, push_ail line), log grant-head bytes and LSN movement, memory,
PSI, and steal — aggregated min/median/max across nodes.  Written for the
sess39 dir_reuse run-over-run degradation loop: compare a fresh run's
window against a plateau run's window.
"""
import sys, re, glob, os, statistics

def parse(path):
    d = {}
    try:
        txt = open(path).read()
    except OSError:
        return None
    m = re.search(r'^log (\d+) (\d+) (\d+) (\d+) (\d+)', txt, re.M)
    if m:
        d['log_writes'], d['log_blocks'], d['log_noiclogs'], d['log_force'], d['log_force_sleep'] = map(int, m.groups())
    m = re.search(r'^push_ail (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+)', txt, re.M)
    if m:
        (d['try_logspace'], d['sleep_logspace'], d['push_ail'], d['pa_success'],
         d['pa_pushbuf'], d['pa_pinned'], d['pa_locked'], d['pa_flushing'],
         d['pa_restarts'], d['pa_flush']) = map(int, m.groups())
    m = re.search(r'reserve_grant_head_bytes (\d+)', txt)
    if m: d['grant_reserve'] = int(m.group(1))
    m = re.search(r'log_head_lsn (\d+):(\d+)', txt)
    if m: d['head_cycle'], d['head_blk'] = int(m.group(1)), int(m.group(2))
    m = re.search(r'log_tail_lsn (\d+):(\d+)', txt)
    if m: d['tail_cycle'], d['tail_blk'] = int(m.group(1)), int(m.group(2))
    m = re.search(r'^Dirty:\s+(\d+)', txt, re.M)
    if m: d['dirty_kb'] = int(m.group(1))
    m = re.search(r'^SUnreclaim:\s+(\d+)', txt, re.M)
    if m: d['sunreclaim_kb'] = int(m.group(1))
    m = re.search(r'^io some avg10=([\d.]+)', txt, re.M)
    if m: d['psi_io10'] = float(m.group(1))
    m = re.search(r'^cpu some avg10=([\d.]+)', txt, re.M)
    if m: d['psi_cpu10'] = float(m.group(1))
    m = re.search(r'^cpu\s+(\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+)', txt, re.M)
    if m:
        d['steal'] = int(m.group(8))
        d['cpu_total'] = sum(int(x) for x in m.groups())
    return d

def main():
    a, b = sys.argv[1], sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else 'tests/logs/sess39_lap'
    deltas = {}
    absol = {}
    for i in range(1, 33):
        pa = parse(os.path.join(out, f'{a}_n{i}.txt'))
        pb = parse(os.path.join(out, f'{b}_n{i}.txt'))
        if not pa or not pb:
            continue
        for k in pb:
            if k in ('psi_io10', 'psi_cpu10', 'grant_reserve', 'dirty_kb',
                     'sunreclaim_kb', 'head_cycle', 'head_blk', 'tail_cycle',
                     'tail_blk'):
                absol.setdefault(k, []).append(pb[k])
            elif k in pa:
                deltas.setdefault(k, []).append(pb[k] - pa[k])
    print(f'== deltas {a} -> {b} (per-node min/med/max across {len(deltas.get("log_writes", []))} nodes) ==')
    for k in sorted(deltas):
        v = sorted(deltas[k])
        if not v: continue
        print(f'  {k:16s} min={v[0]:>9} med={v[len(v)//2]:>9} max={v[-1]:>9}')
    print(f'== absolutes at {b} ==')
    for k in sorted(absol):
        v = sorted(absol[k])
        print(f'  {k:16s} min={v[0]:>9} med={v[len(v)//2]:>9} max={v[-1]:>9}')

if __name__ == '__main__':
    main()
