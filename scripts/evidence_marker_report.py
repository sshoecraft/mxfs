#!/usr/bin/env python3
"""Aggregate the TSV emitted by evidence_marker_census.sh into a per-marker report."""
import os, sys, collections

tsv = sys.argv[1]
markers = [l.rstrip("\n") for l in open(sys.argv[2]) if l.strip()]
EXAMPLE_FOR = {"Corruption of in-memory data", "BUG:", "Oops", "hung_task", "P5D-STALE-SERVED"}

files = set()
per = {m: collections.Counter() for m in markers}   # marker -> dir -> lines
examples = collections.defaultdict(list)

for line in open(tsv, errors="replace"):
    p = line.rstrip("\n").split("\t")
    if p[0] == "F":
        files.add(p[1])
    elif p[0] == "C":
        _, d, f, m, n = p[:5]
        per[m][d] += int(n)
    elif p[0] == "X":
        m = p[1]
        if m in EXAMPLE_FOR and len(examples[m]) < 3:
            examples[m].append((p[2], "\t".join(p[3:])))

mtime = {}
def mt(d):
    if d not in mtime:
        mtime[d] = os.stat(d).st_mtime
    return mtime[d]

print("FILES SCANNED: %d" % len(files))
print("DIRS SCANNED : %d" % len({os.path.dirname(f) for f in files}))
print()
for m in markers:
    c = per[m]
    total = sum(c.values())
    print("MARKER %-28s total_lines=%-9d dirs_with_hits=%d" % (repr(m), total, len(c)))
    if c:
        for d in sorted(c, key=mt, reverse=True)[:5]:
            print("    %-72s %d" % (os.path.basename(d), c[d]))
print()
print("=== EXAMPLES (<=3 each, trimmed 300) ===")
for m in ["Corruption of in-memory data", "BUG:", "Oops", "hung_task", "P5D-STALE-SERVED"]:
    print("--- %s (%d shown)" % (m, len(examples[m])))
    for f, txt in examples[m]:
        print("  %s" % f)
        print("    %s" % txt[:300])
