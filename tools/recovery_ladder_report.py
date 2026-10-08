#!/usr/bin/env python3
"""Where a survivor's recovery of a dead peer spent its time, per kernel log.

Reads the kernel logs a DRBD failover run keeps (tests/pve_pair_failover.sh
writes klog.<host> per step, `journalctl -k -o short-iso`, or the `.full`
variant stamped in epoch seconds) and prints, for each victim incarnation a
host recovered, the ladder from the TCP disconnect to P163-RECOVERY-COMPLETE:

  disc     TCP peer disconnected (the 40 s reconnect grace starts)
  wseen    P163-WITHDRAW-SEEN
  cert     P236-FENCE-CERTIFIED (kind printed)
  rstart   foreign replay of the victim's slice begins
  rdone    foreign replay complete
  purge    P-TAUTH-PURGE (ledger purge; total_ms and the store walls)
  complete P163-RECOVERY-COMPLETE (with its ms walls)
  grace    the TCP grace's end: 'did not reconnect' (declared) or
           P-TCP-SUSPECT-DEPARTED (nothing declared), or P-DRBD-EXCL-DEATH

Times are seconds relative to `cert`.  short-iso stamps are whole seconds,
so every relative time is +-1 s; the walls inside P163-RECOVERY-COMPLETE and
P-TAUTH-PURGE are milliseconds.  `grace_late` is how long after disc + 40 s
the grace's end was logged: the grace checker runs every 500 ms, so anything
past ~1.5 s means its thread was held elsewhere.

usage: tools/recovery_ladder_report.py KLOG [KLOG ...]
"""

import datetime
import re
import sys

STAMP_ISO = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d) ')
STAMP_EPOCH = re.compile(r'^(\d{9,11}\.\d+) ')

EVENTS = [
    ('disc', re.compile(r'TCP peer (\d+) disconnected -- deferring death (\d+) ms')),
    ('wseen', re.compile(r'P163-WITHDRAW-SEEN slot=(\d+) node=(\d+)')),
    ('cert', re.compile(r'P236-FENCE-CERTIFIED slot=(\d+) victim=(\d+) epoch=\d+ kind=(\S+)')),
    ('rstart', re.compile(r'foreign replay of dead slot (\d+) ')),
    ('rdone', re.compile(r'foreign replay of slot (\d+) complete')),
    ('purge', re.compile(r'P-TAUTH-PURGE node=(\d+) slot=(-?\d+) cleared=(\d+) .*?committed=(\d+) batches=(\d+) .*?total_ms=(\d+)(?: store_ms: (.*))?')),
    ('complete', re.compile(r'P163-RECOVERY-COMPLETE slot=(\d+) node=(\d+)(?:.*?ms: (.*))?')),
    ('declared', re.compile(r'TCP peer (\d+) did not reconnect within (\d+) ms')),
    ('departed', re.compile(r'P-TCP-SUSPECT-DEPARTED peer (\d+)')),
    ('excldeath', re.compile(r'P-DRBD-EXCL-DEATH node=(\d+)')),
]


def stamp(line):
    m = STAMP_ISO.match(line)
    if m:
        return datetime.datetime.fromisoformat(m.group(1)).timestamp()
    m = STAMP_EPOCH.match(line)
    if m:
        return float(m.group(1))
    return None


def parse(path):
    """Return {victim node: {event: (t, groups)}}, first occurrence of each
    event after the victim's first sighting, plus the slot each victim held."""
    victims = {}
    slot_of = {}
    order = []
    with open(path, errors='replace') as f:
        for line in f:
            t = stamp(line)
            if t is None:
                continue
            for name, rx in EVENTS:
                m = rx.search(line)
                if not m:
                    continue
                g = m.groups()
                if name == 'disc':
                    node = g[0]
                elif name == 'wseen':
                    node = g[1]
                    slot_of.setdefault(g[0], node)
                elif name == 'cert':
                    node = g[1]
                    slot_of[g[0]] = node
                elif name in ('rstart', 'rdone'):
                    node = slot_of.get(g[0])
                    if node is None:
                        break
                elif name == 'purge':
                    node = g[0]
                elif name == 'complete':
                    node = g[1]
                    slot_of[g[0]] = node
                else:
                    node = g[0]
                v = victims.get(node)
                if v is None:
                    v = victims[node] = {}
                    order.append(node)
                # the first of each, except that a later complete or purge
                # for the same victim (a retry) replaces nothing
                if name not in v:
                    v[name] = (t, g)
                break
    return [(n, victims[n]) for n in order]


def rel(v, name, t0):
    if name not in v:
        return '-'
    return '%+.0f' % (v[name][0] - t0)


def report(path):
    rows = parse(path)
    for node, v in rows:
        if 'complete' not in v and 'cert' not in v:
            continue
        t0 = v['cert'][0] if 'cert' in v else v['complete'][0]
        kind = v['cert'][1][2] if 'cert' in v else '?'
        print('%s victim=%s cert_kind=%s' % (path, node, kind))
        cols = ['disc', 'wseen', 'cert', 'rstart', 'rdone', 'purge', 'complete']
        print('  ' + ' '.join('%s=%s' % (c, rel(v, c, t0)) for c in cols))
        if 'complete' in v and v['complete'][1][2]:
            print('  complete walls: %s' % v['complete'][1][2].strip())
        if 'purge' in v:
            g = v['purge'][1]
            print('  purge: cleared=%s committed=%s batches=%s total_ms=%s store_ms: %s'
                  % (g[2], g[3], g[4], g[5], (g[6] or '').strip()))
        end = None
        for name in ('declared', 'departed', 'excldeath'):
            if name in v:
                end = name
                break
        if end:
            line = '  grace end: %s at %s' % (end, rel(v, end, t0))
            if 'disc' in v:
                grace_ms = int(v['disc'][1][1])
                late = v[end][0] - (v['disc'][0] + grace_ms / 1000.0)
                line += ' (grace_late=%+.0f s)' % late
            if 'complete' in v:
                line += ' — %s the completion' % (
                    'before' if v[end][0] < v['complete'][0] else
                    'after' if v[end][0] > v['complete'][0] else 'same second as')
            print(line)
        if 'rdone' in v and 'complete' in v:
            print('  replay done -> complete: %.0f s; cert -> complete: %.0f s'
                  % (v['complete'][0] - v['rdone'][0], v['complete'][0] - t0))


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    for path in argv[1:]:
        report(path)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
