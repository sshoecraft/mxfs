#!/usr/bin/env python3
"""Count a tests/pve_bio_census.sh trace: bios to the DRBD device and requests
issued to its disk, by flags (rwbs), issuing task and device region; then the
gaps in the disk's request stream.

A SATA disk runs a cache flush as a non-queued command: while one is out,
nothing else is issued to it.  So a gap of GAP_MS or more between two
requests issued to the disk is the disk (or the queue above it) holding
everything, and the requests issued just before it are what it was holding
on.  Each gap is printed with the last LEAD events (bios and requests) before
it and the first request after it.

Usage: tests/pve_bio_census.py <trace> <seconds> [gap_ms (250)] [lead (8)]
"""
import collections
import re
import sys

path, secs = sys.argv[1], float(sys.argv[2])
gap_ms = float(sys.argv[3]) if len(sys.argv) > 3 else 250.0
lead = int(sys.argv[4]) if len(sys.argv) > 4 else 8
# "  fio-1234  [003] ..... 123.456789: block_bio_queue: 147,2 WS 2048 + 256 [fio]"
# "  kworker/3:1H-99 [003] ..... 123.4: block_rq_issue: 8,16 WS 4096 () 2048 + 8 [kworker/3:1H]"
pat = re.compile(r"^\s*(.+?)-(\d+)\s+\[\d+\][^:]*?\s(\d+\.\d+):\s+(block_bio_queue|block_rq_issue):\s+(\d+),(\d+)\s+(\S+)\s+(?:\d+ \(.*?\) )?(\d+) \+ (\d+)")
meta = {}
tally = {"block_bio_queue": collections.Counter(), "block_rq_issue": collections.Counter()}
sect = {"block_bio_queue": collections.Counter(), "block_rq_issue": collections.Counter()}
regions = collections.Counter()
tasks = collections.Counter()
events = []
for line in open(path, errors="replace"):
    if line.startswith("# drbd_dev="):
        meta = dict(kv.split("=") for kv in line[2:].split())
        continue
    m = pat.match(line)
    if not m:
        continue
    comm, ts, ev, rwbs = m.group(1).strip(), float(m.group(3)), m.group(4), m.group(7)
    sector, n = int(m.group(8)), int(m.group(9))
    comm = re.sub(r"[/:]?\d+$", "", comm)       # kworker/u8:3 -> kworker/u8
    tally[ev][rwbs] += 1
    sect[ev][rwbs] += n
    events.append((ts, ev, comm, rwbs, sector, n))
    if ev == "block_bio_queue":
        tasks[(comm, rwbs)] += 1
        regions[(sector * 512 // (64 << 20), rwbs)] += 1

print(f"over {secs:.0f} s; {meta}")
for ev, name in (("block_bio_queue", "bios to the DRBD device"), ("block_rq_issue", "requests issued to the disk")):
    tot = sum(tally[ev].values())
    print(f"{name}: {tot} ({tot / secs:.1f}/s)  rwbs: count, /s, mean KiB")
    for rwbs, c in tally[ev].most_common():
        print(f"  {rwbs:6s} {c:8d} {c / secs:8.1f} {sect[ev][rwbs] * 512 / 1024 / max(c, 1):8.1f}")
print("bios by task and rwbs (top 25): count, /s")
for (comm, rwbs), c in tasks.most_common(25):
    print(f"  {comm:24s} {rwbs:6s} {c:8d} {c / secs:8.1f}")
print("bios by 64 MiB region of the device and rwbs (top 25): region start MiB, rwbs, count")
for (reg, rwbs), c in regions.most_common(25):
    print(f"  {reg * 64:8d} {rwbs:6s} {c:8d}")

events.sort()
rq = [i for i, e in enumerate(events) if e[1] == "block_rq_issue"]
gaps = []
for a, b in zip(rq, rq[1:]):
    d = (events[b][0] - events[a][0]) * 1000
    if d >= gap_ms:
        gaps.append((a, b, d))
tot = sum(d for _, _, d in gaps)
print(f"gaps of {gap_ms:.0f} ms or more between requests issued to the disk: {len(gaps)}, {tot / 1000:.1f} s in all "
      f"({100 * tot / 1000 / secs:.1f}% of the run)")
# which request the disk was last given before each gap (its flags, who
# issued it): a gap that always follows a flush is the disk running it
last = collections.Counter()
lastms = collections.Counter()
for a, b, d in gaps:
    e = events[a]
    last[(e[3], e[2])] += 1
    lastms[(e[3], e[2])] += d
print("  the last request issued before each gap: rwbs, task, gaps, s in them")
for k, c in last.most_common(10):
    print(f"    {k[0]:6s} {k[1]:20s} {c:5d} {lastms[k] / 1000:7.1f}")
def fmt(e, t0):
    ts, ev, comm, rwbs, sector, n = e
    kind = "bio" if ev == "block_bio_queue" else "rq "
    return f"    {1000 * (ts - t0):+9.1f} ms {kind} {rwbs:6s} {comm:16s} sector={sector} KiB={n * 512 // 1024}"
for a, b, d in gaps[:12]:
    t0 = events[a][0]
    print(f"  gap {d:.0f} ms after t={t0:.3f}:")
    for e in events[max(0, a - lead + 1):a + 1]:
        print(fmt(e, t0))
    during = events[a + 1:b]
    for e in during[:10]:
        print(fmt(e, t0) + "   (queued during the gap)")
    if len(during) > 10:
        print(f"    ... {len(during) - 10} more bios queued during the gap")
    print(fmt(events[b], t0) + "   (first request after it)")
