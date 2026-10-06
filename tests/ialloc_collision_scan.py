#!/usr/bin/env python3
"""Merge P150-ALLOC/FREE inode-allocation events from per-node kernel logs,
find inodes ALLOCated twice with no FREE between (merged realns order),
and print supporting raw evidence.  Read-only.

usage: ialloc_collision_scan.py DIR [FILENAME]
DIR holds test<N>/FILENAME for each node."""
import os, re, sys, collections

base = sys.argv[1]
fname = sys.argv[2] if len(sys.argv) > 2 else "mxfs_pf_kmsg.20261005T010552Z-g8.path_failover"
nodes = sorted([d for d in os.listdir(base) if d.startswith("test")
                and os.path.exists(os.path.join(base, d, fname))],
               key=lambda d: int(d[4:]))

stamp = re.compile(r'^\[\s*([0-9]+\.[0-9]+)\]')
realre = re.compile(r'realns=(\d+)')
evre = re.compile(r'(P150-[A-Z0-9-]+) agno=(\d+) startino=(\d+) off=(\d+)')
shapere = re.compile(r'corrupt|EUCLEAN|EFSCORRUPTED|shutdown|WARN|BUG:|double', re.I)
EXCL = ("P150-", "P-AGIFC-MOD", "P144-WR", "P145-ALLOC", "buf_io")


def path(n):
    return os.path.join(base, n, fname)


# ---- pass 1
evcount = {n: collections.Counter() for n in nodes}
events = []            # (realns, nodeidx, lineno, kind, agno, ino, line)
norealns = collections.Counter()
alloc_ag = {n: collections.Counter() for n in nodes}
alloc_ag_fin = {n: collections.Counter() for n in nodes}
dupes = collections.Counter()
nlines = {}
shapes = collections.defaultdict(collections.Counter)   # shape -> node -> count
shape_example = {}
match_total = collections.Counter()
for ni, n in enumerate(nodes):
    seen = set()
    with open(path(n), "rb") as fh:
        for ln, raw in enumerate(fh, 1):
            line = raw.decode("latin-1").rstrip("\n")
            if shapere.search(line):
                match_total[n] += 1
                shp = re.sub(r'\d+', 'N', line)[:110]
                shapes[shp][n] += 1
                shape_example.setdefault(shp, (n, ln, line))
            if "P150-" not in line:
                continue
            m = evre.search(line)
            if not m:
                continue
            name, agno, start, off = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
            evcount[n][name] += 1
            if line in seen:
                dupes[n] += 1
            seen.add(line)
            if name == "P150-ALLOC-UI":
                alloc_ag[n][agno] += 1
            if name == "P150-ALLOC-FIN":
                alloc_ag_fin[n][agno] += 1
            r = realre.search(line)
            if not r:
                norealns[n] += 1
                continue
            events.append((int(r.group(1)), ni, ln, name, agno, start + off, line))
        nlines[n] = ln

print("=== nodes/files:", {n: nlines[n] for n in nodes})
print("\n=== 1. P150 event names per node")
allnames = sorted({k for n in nodes for k in evcount[n]})
print("%-16s" % "event" + "".join("%9s" % n for n in nodes) + "%10s" % "total")
for k in allnames:
    print("%-16s" % k + "".join("%9d" % evcount[n][k] for n in nodes)
          + "%10d" % sum(evcount[n][k] for n in nodes))
print("P150 lines w/o realns (excluded from merge):", dict(norealns) or 0)
print("exact-duplicate P150 lines within a node:", dict(dupes) or 0)

# ---- task 2
for use in (("P150-ALLOC-UI", "P150-FREE-IBT"), ("P150-ALLOC-FIN", "P150-FREE-FIN")):
    evs = sorted([e for e in events if e[3] in use], key=lambda e: (e[0], e[1], e[2]))
    state = {}
    coll = []
    for e in evs:
        key = (e[4], e[5])
        if e[3] == use[0]:
            prev = state.get(key)
            if prev is not None:
                coll.append((prev, e))
            state[key] = e
        else:
            state[key] = None
    pairs = collections.Counter((nodes[a[1]], nodes[b[1]]) for a, b in coll)
    perN = collections.Counter(nodes[e[1]] for e in evs)
    print("\n=== 2. collisions using %s / %s" % use)
    print("events parsed per node (alloc+free):", dict(perN), "total", len(evs))
    print("TOTAL COLLISIONS: %d (of %d %s events)" % (len(coll), sum(1 for e in evs if e[3] == use[0]), use[0]))
    print("per (first-node, second-node):", dict(pairs))
    ident = sum(1 for a, b in coll if a[6] == b[6])
    print("collisions where both lines are byte-identical:", ident)
    for i, (a, b) in enumerate(coll[:15], 1):
        print("--- #%d agno=%d ino=%d gap_ns=%d (%.6f s)" % (i, a[4], a[5], b[0] - a[0], (b[0] - a[0]) / 1e9))
        print("  FIRST  %s %s" % (nodes[a[1]], a[6]))
        print("  SECOND %s %s" % (nodes[b[1]], b[6]))
    if use[0] == "P150-ALLOC-UI":
        uicoll = coll

# ---- task 3
print("\n=== 3. ALLOC by agno per node (UI count / FIN count)")
allag = sorted({a for n in nodes for a in alloc_ag[n]} | {a for n in nodes for a in alloc_ag_fin[n]})
print("%-8s" % "node" + "".join("%10s" % ("ag%d" % a) for a in allag))
for n in nodes:
    print("%-8s" % n + "".join("%10s" % ("%d/%d" % (alloc_ag[n][a], alloc_ag_fin[n][a])) for a in allag))

# ---- task 4
print("\n=== 4. non-P150 lines for ag in the 3 earliest collisions")


def window_lines(n, agno, t0, t1):
    pats = ("ag=%d " % agno, "agno=%d " % agno)
    out = []
    off = None
    with open(path(n), "rb") as fh:
        for ln, raw in enumerate(fh, 1):
            line = raw.decode("latin-1").rstrip("\n")
            r = realre.search(line)
            s = stamp.match(line)
            up = float(s.group(1)) * 1e9 if s else None
            if r:
                t = int(r.group(1))
                if up is not None:
                    off = t - up
            elif up is not None and off is not None:
                t = up + off
            else:
                continue
            if t < t0 or t > t1:
                continue
            if not any(p in line for p in pats):
                continue
            if any(x in line for x in EXCL):
                continue
            out.append((ln, line))
    return out


for i, (a, b) in enumerate(uicoll[:3], 1):
    agno = a[4]
    t0 = a[0] - 3_000_000_000
    t1 = b[0] + 1_000_000_000
    print("\n##### collision #%d agno=%d ino=%d window realns [%d, %d]" % (i, agno, a[5], t0, t1))
    for n in sorted({nodes[a[1]], nodes[b[1]]}, key=lambda x: int(x[4:])):
        res = window_lines(n, agno, t0, t1)
        print("--- %s: %d matching lines before cap, printing %d" % (n, len(res), min(80, len(res))))
        for ln, line in res[:80]:
            print("%s:%d: %s" % (n, ln, line[:400]))

# ---- task 5
print("\n=== 5. corrupt|EUCLEAN|EFSCORRUPTED|shutdown|WARN|BUG:|double (case-insens)")
print("matching lines per node:", dict(match_total), "total", sum(match_total.values()))
print("distinct shapes:", len(shapes))
top = sorted(shapes.items(), key=lambda kv: -sum(kv[1].values()))
print("top 25 shapes (of %d), per-node counts, then first verbatim line (node:line)" % len(shapes))
for shp, c in top[:25]:
    print("\nSHAPE total=%d per-node=%s" % (sum(c.values()), {n: c[n] for n in nodes if c[n]}))
    print("  shape: %s" % shp)
    n, ln, line = shape_example[shp]
    print("  e.g. %s:%d: %s" % (n, ln, line[:400]))
