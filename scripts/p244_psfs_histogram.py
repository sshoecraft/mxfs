#!/usr/bin/env python3
"""Pair each P244-REL-TERMINAL-DEFER line with the nearest preceding
P-SFS line for the same inode, and histogram the deltas plus the
P244 c1= / ili_f= fields.

Usage: p244_psfs_histogram.py <dmesg_file> [<dmesg_file> ...]

Line shape: '[<ts>] mxfs: TAG ino=N key=val ...' with ts in seconds.
"""
import re
import sys
from collections import defaultdict, Counter

TS = re.compile(r'^\[\s*(\d+\.\d+)\]')
INO = re.compile(r'\bino=(\d+)\b')
C1 = re.compile(r'\bc1=(-?\d+)\b')
ILI = re.compile(r'\bili_f=(\S+)')

DELTA_BUCKETS = ['<1', '1-5', '5-20', '20-100', '>100', 'none-found-within-200ms']
C1_BUCKETS = ['<1000', '1000-5000', '5000-50000', '>50000']
WINDOW_MS = 200.0


def delta_bucket(ms):
    if ms < 1:
        return '<1'
    if ms < 5:
        return '1-5'
    if ms < 20:
        return '5-20'
    if ms < 100:
        return '20-100'
    return '>100'


def c1_bucket(v):
    if v < 1000:
        return '<1000'
    if v < 5000:
        return '1000-5000'
    if v < 50000:
        return '5000-50000'
    return '>50000'


def analyze(path):
    last_psfs = {}                       # ino -> ts (seconds), most recent seen
    deltas = {'1': Counter(), '0': Counter()}
    c1_hist = Counter()
    ili_hist = Counter()
    totals = Counter()

    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            m = TS.match(line)
            if not m:
                continue
            ts = float(m.group(1))

            if 'P-SFS' in line:
                mi = INO.search(line)
                if mi:
                    last_psfs[mi.group(1)] = ts
                continue

            if 'P244-REL-TERMINAL-DEFER' not in line:
                continue

            totals['P244'] += 1
            live = '1' if 'live=1' in line else ('0' if 'live=0' in line else None)
            if live is None:
                totals['live_missing'] += 1
                continue
            totals['live=' + live] += 1

            mi = INO.search(line)
            prev = last_psfs.get(mi.group(1)) if mi else None
            if prev is None:
                deltas[live]['none-found-within-200ms'] += 1
            else:
                dms = (ts - prev) * 1000.0
                if dms < 0 or dms > WINDOW_MS:
                    deltas[live]['none-found-within-200ms'] += 1
                else:
                    deltas[live][delta_bucket(dms)] += 1

            if live == '1':
                mc = C1.search(line)
                c1_hist[c1_bucket(int(mc.group(1))) if mc else 'no-c1-field'] += 1
                ml = ILI.search(line)
                ili_hist[ml.group(1) if ml else 'no-ili_f-field'] += 1

    return deltas, c1_hist, ili_hist, totals


def main():
    for path in sys.argv[1:]:
        deltas, c1_hist, ili_hist, totals = analyze(path)
        print('=== %s' % path)
        print('total P244        : %d' % totals['P244'])
        print('  live=1          : %d' % totals['live=1'])
        print('  live=0          : %d' % totals['live=0'])
        if totals['live_missing']:
            print('  live= absent    : %d' % totals['live_missing'])
        for live in ('1', '0'):
            tot = sum(deltas[live].values())
            print('P244 live=%s delta(P244.ts - nearest preceding P-SFS same ino), ms  [n=%d]' % (live, tot))
            for b in DELTA_BUCKETS:
                print('    %-24s %d' % (b, deltas[live][b]))
        tot = sum(c1_hist.values())
        print('live=1 c1= (us) [n=%d]' % tot)
        for b in C1_BUCKETS:
            print('    %-24s %d' % (b, c1_hist[b]))
        for k in sorted(k for k in c1_hist if k not in C1_BUCKETS):
            print('    %-24s %d' % (k, c1_hist[k]))
        tot = sum(ili_hist.values())
        print('live=1 ili_f= values [n=%d]' % tot)
        for k, v in sorted(ili_hist.items(), key=lambda kv: (-kv[1], kv[0])):
            print('    %-24s %d' % (k, v))
        print()


if __name__ == '__main__':
    main()
