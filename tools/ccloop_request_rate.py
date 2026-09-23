#!/usr/bin/env python3
"""
ccloop_request_rate.py — denominator for the refusal audit.

Counts API requests per UTC day (unique requestId on assistant rows) and the
context size each carried, so the safeguard-flag RATE can be computed instead
of a bare count.  Regex-scans rather than json.loads-ing 480MB.
"""
import os, glob, re, collections, sys

PROJ = os.path.expanduser('~/.claude/projects/-src-mxfs')
RE_REQ = re.compile(rb'"requestId":"(req_[A-Za-z0-9]+)"')
RE_TS  = re.compile(rb'"timestamp":"(\d{4}-\d{2}-\d{2})T')
RE_IN  = re.compile(rb'"input_tokens":(\d+)')
RE_CR  = re.compile(rb'"cache_read_input_tokens":(\d+)')
RE_CC  = re.compile(rb'"cache_creation_input_tokens":(\d+)')

perday = collections.Counter()
seen = set()
ctxbin = collections.Counter()          # (day, bin) -> requests
DAYS = {b'2026-08-21', b'2026-08-22', b'2026-08-23'}

for fp in glob.glob(os.path.join(PROJ, '*.jsonl')):
    with open(fp, 'rb') as fh:
        for line in fh:
            m = RE_REQ.search(line)
            if not m: continue
            rid = m.group(1)
            if rid in seen: continue
            seen.add(rid)
            d = RE_TS.search(line)
            if not d: continue
            day = d.group(1)
            perday[day.decode()] += 1
            if day in DAYS:
                tot = 0
                for r in (RE_IN, RE_CR, RE_CC):
                    mm = r.search(line)
                    if mm: tot += int(mm.group(1))
                b = 'a:<100k' if tot < 100_000 else 'b:100-250k' if tot < 250_000 else 'c:250-400k' if tot < 400_000 else 'd:>400k'
                ctxbin[(day.decode(), b)] += 1

print("=== requests per UTC day (unique requestId) ===")
flags = {'2026-07-26':1,'2026-08-01':1,'2026-08-02':1,'2026-08-07':1,'2026-08-22':10,'2026-08-23':19}
for k in sorted(perday):
    if k < '2026-07-20': continue
    n = perday[k]
    f = flags.get(k, 0)
    rate = (f / n * 1000) if n else 0
    print("  %s  requests=%-6d flags=%-3d  flags/1k_req=%.2f" % (k, n, f, rate))

print()
print("=== requests by context size, Aug 21-23 ===")
for day in sorted({k[0] for k in ctxbin}):
    row = {b: ctxbin[(day, b)] for b in ('a:<100k','b:100-250k','c:250-400k','d:>400k')}
    print("  %s  %s" % (day, row))
