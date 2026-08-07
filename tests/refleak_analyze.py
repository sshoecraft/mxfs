#!/usr/bin/env python3
# refleak_analyze.py — analyze a refleak_trace.sh capture for one inode.
#
#   tests/refleak_analyze.py <tracefile> <ino> [--all]
#
# Prints the full event timeline for the inode number and the per-task net
# reference balance (igrab/ihold/__iget = +1, iput = -1).  igrab can FAIL
# (returns NULL on I_FREEING) — a failed igrab still logs an event here, so
# treat a task whose "+1" is a lone igrab with cnt staying flat as suspect of
# a failed grab, and cross-check cnt sequences.  The leaked-local hypothesis
# (D-UNMOUNT-BUSY-INODES) predicts one task net +1 beyond the known arm
# hand-off pattern (arm igrab in task A, xfs_irele in a kworker).
#
# LIFO-free: uses the complete event sequence, not level pairing.
import re, sys
from collections import defaultdict

if len(sys.argv) < 3:
    sys.exit("usage: refleak_analyze.py <tracefile> <ino> [--all]")
path, target = sys.argv[1], int(sys.argv[2])
show_all = "--all" in sys.argv

# trace line: "  comm-pid  [cpu] flags ts: probe: (sym+0x0/..) ptr=0x.. ino=N cnt=M"
rx = re.compile(
    r"^\s*(?P<comm>.+?)-(?P<pid>\d+)\s+\[(?P<cpu>\d+)\]\s+\S+\s+"
    r"(?P<ts>[\d.]+):\s+(?P<probe>\w+):.*?ptr=(?P<ptr>0x[0-9a-f]+)\s+"
    r"ino=(?P<ino>\d+)\s+cnt=(?P<cnt>-?\d+)")

DELTA = {"igrab": +1, "ihold": +1, "iget": +1, "iput": -1}
events = []
with open(path, errors="replace") as f:
    for line in f:
        m = rx.match(line)
        if not m:
            continue
        if int(m["ino"]) != target:
            continue
        events.append((float(m["ts"]), m["comm"], int(m["pid"]),
                       m["probe"], m["ptr"], int(m["cnt"])))

if not events:
    sys.exit(f"no events for ino {target} in {path}")

# ptr sanity: an ino can be reused across incarnations with different ptrs
ptrs = defaultdict(int)
for e in events:
    ptrs[e[4]] += 1
print(f"# {len(events)} events for ino {target}; ptrs: "
      + ", ".join(f"{p}({c})" for p, c in sorted(ptrs.items(), key=lambda x: -x[1])))

bal = defaultdict(int)
first = events[0][0]
for ts, comm, pid, probe, ptr, cnt in events:
    bal[(comm, pid, ptr)] += DELTA.get(probe, 0)
    if show_all or len(events) <= 400:
        print(f"{ts-first:10.6f} {comm:>16}-{pid:<7} {probe:>5} cnt={cnt:<3} {ptr}")

print("\n# per-task net balance (nonzero only):")
for (comm, pid, ptr), n in sorted(bal.items(), key=lambda x: -abs(x[1])):
    if n:
        print(f"  net {n:+d}  {comm}-{pid}  {ptr}")
print("\n# tail (last 25 events):")
for ts, comm, pid, probe, ptr, cnt in events[-25:]:
    print(f"{ts-first:10.6f} {comm:>16}-{pid:<7} {probe:>5} cnt={cnt:<3} {ptr}")
