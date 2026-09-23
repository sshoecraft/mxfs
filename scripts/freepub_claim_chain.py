#!/usr/bin/env python3
"""freepub_claim_chain.py — sess431 (D-0351) FREE-publication claim chain check.

Input: one or more raw kernel-log files (journalctl -k / dmesg text, any
prefix; lines are matched on the 'mxfs: P-FREEPUB-*' tags).  For every
claim (P-FREEPUB-CLAIM ino= gen= epoch= seq=) the script follows the chain
the design-consult ruling asks to be proven per inode:

    P-FREEPUB-CLAIM  ->  P-FREEPUB-KEEP (merge kept the slot)
                     ->  P-FREEPUB-WRITE (mask included the slot)
                     ->  P-FREEPUB-CLAIM-CLEAR why=durable (completion)

and reports, per claim, which links were seen and how the claim ended
(durable / abort / pub-skipped / merge-overlaid / recycle / discharge-<why> /
NONE).  Any P-FREEPUB-CLAIM-STALE line and any P238 rollback with
cls=freepub-stale is listed verbatim.  A claim that ended other than
'durable' or a discharge, or that was never cleared, is a defect signal for
the ledger — it is NOT diagnosed here.

Usage: scripts/freepub_claim_chain.py <log> [<log> ...]
Exit 0 if every claim ended durable (or a home-free/foreign discharge) and no
STALE lines; 1 otherwise.
"""
import re
import sys
from collections import defaultdict

TS = re.compile(r'^\[\s*([0-9.]+)\]\s+(\S+)\s+kernel:\s+(.*)$')
INO = re.compile(r'\bino=(\d+)')
KV = re.compile(r'\b(gen|epoch|seq|why)=([^\s]+)')


def parse(path):
    node = None
    for line in open(path, errors='replace'):
        line = line.rstrip('\n')
        m = TS.match(line)
        if m:
            t, node, rest = float(m.group(1)), m.group(2), m.group(3)
        else:
            t, rest = None, line
        if 'P-FREEPUB-' not in rest and 'cls=freepub-stale' not in rest:
            continue
        mi = INO.search(rest)
        ino = int(mi.group(1)) if mi else None
        kv = dict(KV.findall(rest))
        yield path, node, t, ino, kv, rest


def main(paths):
    claims = defaultdict(list)     # (path,node,ino) -> list of claim dicts
    stale = []
    total = 0
    for path, node, t, ino, kv, rest in (ev for p in paths for ev in parse(p)):
        total += 1
        key = (path, node, ino)
        if 'P-FREEPUB-CLAIM-STALE' in rest or 'cls=freepub-stale' in rest:
            stale.append((node, t, rest))
            continue
        if 'P-FREEPUB-CLAIM ' in rest:
            claims[key].append({'t': t, 'gen': kv.get('gen'),
                                'epoch': kv.get('epoch'), 'keep': 0,
                                'write': 0, 'end': None, 'end_t': None})
            continue
        if not claims[key]:
            # KEEP/WRITE/CLEAR without a claim line (probe cap or log window)
            claims[key].append({'t': None, 'gen': kv.get('gen'),
                                'epoch': kv.get('epoch'), 'keep': 0,
                                'write': 0, 'end': None, 'end_t': None,
                                'orphan': True})
        cur = claims[key][-1]
        if 'P-FREEPUB-KEEP' in rest:
            cur['keep'] += 1
        elif 'P-FREEPUB-WRITE' in rest:
            cur['write'] += 1
        elif 'P-FREEPUB-CLAIM-CLEAR' in rest:
            cur['end'] = kv.get('why', '?')
            cur['end_t'] = t

    ends = defaultdict(int)
    bad = []
    n = 0
    for key, lst in claims.items():
        for c in lst:
            n += 1
            e = c['end'] or 'NONE'
            ends[e] += 1
            ok = e == 'durable' or e.startswith('home-free') or e == 'flushed' \
                or e == 'foreign' or e == 'superseded' or e == 'iunlink_remove'
            # keep is optional: mxfs_iflush_cluster_merge_dirs returns before
            # its item loop when the buffer holds no foreign allocated slot,
            # so a claim can go CLAIM -> WRITE -> durable with no KEEP line.
            if not ok or (e == 'durable' and c['write'] == 0):
                bad.append((key, c))
    print(f"freepub chain: lines={total} claims={n} stale_lines={len(stale)}")
    print("ends: " + " ".join(f"{k}={v}" for k, v in sorted(ends.items())))
    keeps = sum(c['keep'] for l in claims.values() for c in l)
    writes = sum(c['write'] for l in claims.values() for c in l)
    print(f"keep_lines={keeps} write_lines={writes}")
    for node, t, rest in stale[:50]:
        print(f"STALE {node} [{t}] {rest[:220]}")
    if len(stale) > 50:
        print(f"... {len(stale) - 50} more STALE lines")
    for (path, node, ino), c in bad[:60]:
        print(f"BAD {node} ino={ino} t={c['t']} gen={c['gen']} epoch={c['epoch']} "
              f"keep={c['keep']} write={c['write']} end={c['end']} "
              f"{'(orphan: no CLAIM line)' if c.get('orphan') else ''}")
    if len(bad) > 60:
        print(f"... {len(bad) - 60} more BAD claims")
    print(f"RESULT {'PASS' if not bad and not stale else 'FAIL'} bad={len(bad)} stale={len(stale)}")
    return 0 if not bad and not stale else 1


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
