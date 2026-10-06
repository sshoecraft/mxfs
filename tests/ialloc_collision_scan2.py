#!/usr/bin/env python3
"""Data-extent (P145) overlap analysis, python3 per-node lap mapping and
cross-node inode-number grep over per-node kernel logs.  Read-only.

usage: ialloc_collision_scan2.py DIR [FILENAME]
DIR holds test<N>/FILENAME for each node.  Sections A, B, C as in the
request; each prints a '=== ' header so line ranges can be located."""
import os, re, sys, bisect, collections

base = sys.argv[1]
fname = sys.argv[2] if len(sys.argv) > 2 else "mxfs_pf_kmsg.20261005T010552Z-g8.path_failover"
nodes = sorted([d for d in os.listdir(base) if d.startswith("test")
                and os.path.exists(os.path.join(base, d, fname))],
               key=lambda d: int(d[4:]))
THRESH = 1791164356000000000      # 1 s before test11's first end-of-row python3 alloc
stamp = re.compile(r'^\[\s*([0-9]+\.[0-9]+)\]')
realre = re.compile(r'realns=(\d+)')
p145 = re.compile(r'mxfs: (P145-[A-Z0-9-]+) agno=(\d+) bno=(\d+) len=(\d+)')
extshape = re.compile(r'agno=\d+ bno=\d+ len=\d+')
alloc150 = re.compile(r'P150-ALLOC-UI agno=(\d+) startino=(\d+) off=(\d+)')
rem82 = re.compile(r'P82-REM ino=(\d+) agno=(\d+) agino=0x([0-9a-f]+)')
inore = re.compile(r'(?<![A-Za-z])ino=(\d+)')
namere = re.compile(r'(?<![0-9A-Za-z])f0000\d{3}(?![0-9A-Za-z])')
agifc = re.compile(r'P-AGIFC-MOD site=dialloc_ag agno=(\d+) delta=-1')
FOCUS = ("test7", "test11")


def path(n):
    return os.path.join(base, n, fname)


# ------------------------------------------------------------ pass 1
p145names = {n: collections.Counter() for n in nodes}
p145ex = collections.defaultdict(list)
othershape = collections.defaultdict(collections.Counter)
ext = []            # (realns, nodeidx, ln, name, agno, bno, len, line)
focus = {n: [] for n in FOCUS}          # B candidates
p87 = {n: [] for n in FOCUS}
pyino = {n: collections.OrderedDict() for n in FOCUS}   # ino -> [count, ln, line, t]
pyalloc = {n: [] for n in FOCUS}        # python3 P150-ALLOC-UI: (ln, t, agno, startino, off, line)
pyfirst = {}
agifc_all = {n: collections.Counter() for n in nodes}
agifc_py = {n: 0 for n in nodes}
ui_all = {n: 0 for n in nodes}
ui_py = {n: 0 for n in nodes}
rem_total = rem_ok = 0
rem_bad = []
nlines = {}
for ni, n in enumerate(nodes):
    off = None
    with open(path(n), "rb") as fh:
        for ln, raw in enumerate(fh, 1):
            line = raw.decode("latin-1").rstrip("\n")
            s = stamp.match(line)
            up = float(s.group(1)) * 1e9 if s else None
            r = realre.search(line)
            if r:
                t = int(r.group(1))
                if up is not None:
                    off = t - up
            elif up is not None and off is not None:
                t = int(up + off)
            else:
                t = None
            py = "comm=python3" in line
            if "P145-" in line:
                m = p145.search(line)
                if m:
                    name = m.group(1)
                    p145names[n][name] += 1
                    if len(p145ex[name]) < 2 * len(nodes):
                        p145ex[name].append((n, ln, line))
                    if name == "P145-ALLOC" or name == "P145-FREE":
                        ext.append((t, ni, ln, name, int(m.group(2)), int(m.group(3)), int(m.group(4)), line))
            if extshape.search(line) and "P145-ALLOC" not in line:
                nm = re.search(r'mxfs: (\S+)', line)
                shp = (nm.group(1) if nm else "?") + " " + re.sub(r'\d+', 'N', line.split("mxfs:", 1)[-1])[:110]
                othershape[shp][n] += 1
            if "P-AGIFC-MOD" in line:
                a = agifc.search(line)
                if a:
                    agifc_all[n][int(a.group(1))] += 1
                    if py:
                        agifc_py[n] += 1
            if "P150-ALLOC-UI" in line:
                ui_all[n] += 1
                if py:
                    ui_py[n] += 1
            if "P82-REM" in line:
                m = rem82.search(line)
                if m:
                    rem_total += 1
                    if int(m.group(1)) == (int(m.group(2)) << 22) + int(m.group(3), 16):
                        rem_ok += 1
                    elif len(rem_bad) < 5:
                        rem_bad.append((n, ln, line))
            if n in FOCUS:
                if "P87-OPEN-CHECK" in line:
                    p87[n].append((ln, t, line))
                if py:
                    if "P150-ALLOC-UI" in line:
                        m = alloc150.search(line)
                        pyalloc[n].append((ln, t, int(m.group(1)), int(m.group(2)), int(m.group(3)), line))
                    kind = None
                    if "P150-ALLOC-UI" in line:
                        kind = "P150-ALLOC-UI"
                    elif "P150-FREE-IBT" in line:
                        kind = "P150-FREE-IBT"
                    elif "P145-ALLOC" in line:
                        kind = "P145-ALLOC"
                    elif inore.search(line) and namere.search(line):
                        kind = "ino+name"
                    if kind:
                        focus[n].append((ln, t, kind, line))
                    mi = inore.search(line)
                    if mi:
                        d = pyino[n].setdefault(int(mi.group(1)), [0, ln, line, t])
                        d[0] += 1
                    if n not in pyfirst:
                        pyfirst[n] = (ln, line)
        nlines[n] = ln

print("nodes:", nodes, "lines:", nlines)
print("THRESH realns (end-of-row cutoff used for 'end of row' lists):", THRESH)

# ------------------------------------------------------------ A1
print("\n=== A1. P145 event names per node")
names = sorted({k for n in nodes for k in p145names[n]})
print("%-12s" % "event" + "".join("%9s" % n for n in nodes) + "%9s" % "total")
for k in names:
    print("%-12s" % k + "".join("%9d" % p145names[n][k] for n in nodes) + "%9d" % sum(p145names[n][k] for n in nodes))
for k in names:
    print("-- 2 verbatim examples of %s" % k)
    for n, ln, line in p145ex[k][:2]:
        print("  %s:%d: %s" % (n, ln, line[:300]))
print("\nlines matching 'agno=N bno=N len=N' that are not P145-ALLOC, by shape (digits->N, 110 chars):")
for shp, c in sorted(othershape.items(), key=lambda kv: -sum(kv[1].values())):
    print("  %6d %s  per-node=%s" % (sum(c.values()), shp, {n: c[n] for n in nodes if c[n]}))

# ------------------------------------------------------------ A2
print("\n=== A2. P145-ALLOC (and P145-FREE) count by agno per node")
for nm in ("P145-ALLOC", "P145-FREE"):
    cnt = {n: collections.Counter() for n in nodes}
    for e in ext:
        if e[3] == nm:
            cnt[nodes[e[1]]][e[4]] += 1
    ags = sorted({a for n in nodes for a in cnt[n]})
    print("-- %s" % nm)
    print("%-8s" % "node" + "".join("%7s" % ("ag%d" % a) for a in ags) + "%8s" % "total")
    for n in nodes:
        print("%-8s" % n + "".join("%7d" % cnt[n][a] for a in ags) + "%8d" % sum(cnt[n].values()))

# ------------------------------------------------------------ A3
print("\n=== A3. P145-ALLOC overlaps")
noreal = sum(1 for e in ext if e[0] is None)
print("P145 ext events:", len(ext), "without realns:", noreal)
ext = [e for e in ext if e[0] is not None]
ext.sort(key=lambda e: (e[0], e[1], e[2]))
byag = collections.defaultdict(list)
for idx, e in enumerate(ext):
    byag[e[4]].append((idx, e))
raw_cross = collections.Counter()
raw_same = collections.Counter()
live_pairs = []
for agno, lst in byag.items():
    # raw overlaps (ignore frees)
    al = [(e[5], e[5] + e[6], idx, e[1]) for idx, e in lst if e[3] == "P145-ALLOC"]
    al.sort()
    active = []
    for s, en, idx, nd in al:
        active = [a for a in active if a[1] > s]
        for a in active:
            key = (nodes[a[3]], nodes[nd])
            if a[3] == nd:
                raw_same[key] += 1
            else:
                raw_cross[key] += 1
        active.append((s, en, idx, nd))
    # live-segment overlaps (frees remove coverage)
    segs = []
    for idx, e in lst:
        s, en = e[5], e[5] + e[6]
        if e[3] == "P145-FREE":
            new = []
            for a in segs:
                if a[1] <= s or a[0] >= en:
                    new.append(a)
                else:
                    if a[0] < s:
                        new.append((a[0], s, a[2]))
                    if a[1] > en:
                        new.append((en, a[1], a[2]))
            segs = new
        else:
            seen = set()
            for a in segs:
                if a[0] < en and s < a[1] and a[2] not in seen:
                    seen.add(a[2])
                    live_pairs.append((a[2], idx))
            segs.append((s, en, idx))
tot_rc, tot_rs = sum(raw_cross.values()), sum(raw_same.values())
lp_cross = [p for p in live_pairs if ext[p[0]][1] != ext[p[1]][1]]
lp_same = [p for p in live_pairs if ext[p[0]][1] == ext[p[1]][1]]
print("P145-FREE exists (see A1): overlap pairs are reported both ignoring frees and with frees applied.")
print("RAW overlapping ALLOC pairs, ignoring frees: cross-node %d, same-node %d" % (tot_rc, tot_rs))
print("LIVE overlaps (no free covering the overlapped blocks between the two): cross-node %d, same-node %d" % (len(lp_cross), len(lp_same)))
print("excluded by an intervening free: cross-node %d, same-node %d" % (tot_rc - len(lp_cross), tot_rs - len(lp_same)))
print("raw cross-node per (first,second):", dict(raw_cross))
print("live cross-node per (first,second):", dict(collections.Counter((nodes[ext[a][1]], nodes[ext[b][1]]) for a, b in lp_cross)))
print("live same-node per node:", dict(collections.Counter(nodes[ext[a][1]] for a, b in lp_same)))
lp_cross.sort(key=lambda p: (ext[p[1]][0], ext[p[0]][0]))
for i, (a, b) in enumerate(lp_cross[:20], 1):
    ea, eb = ext[a], ext[b]
    lo, hi = max(ea[5], eb[5]), min(ea[5] + ea[6], eb[5] + eb[6])
    print("--- #%d agno=%d overlap blocks [%d,%d) gap_ns=%d" % (i, ea[4], lo, hi, eb[0] - ea[0]))
    print("  FIRST  %s:%d: %s" % (nodes[ea[1]], ea[2], ea[7]))
    print("  SECOND %s:%d: %s" % (nodes[eb[1]], eb[2], eb[7]))
print("(live cross-node pairs total %d; printed %d)" % (len(lp_cross), min(20, len(lp_cross))))

# ------------------------------------------------------------ B
print("\n=== B0. instrument coverage: python3 inode allocation events")
for n in nodes:
    print("%-7s P150-ALLOC-UI total=%d python3=%d | P-AGIFC-MOD site=dialloc_ag delta=-1 total=%d python3=%d" % (
        n, ui_all[n], ui_py[n], sum(agifc_all[n].values()), agifc_py[n]))
print("first comm=python3 line per focus node:")
for n in FOCUS:
    print("  %s:%d: %s" % (n, pyfirst[n][0], pyfirst[n][1][:260]))
for n, cap in (("test11", 40), ("test7", 120)):
    items = focus[n]
    # P87 lines whose ino is one of this node's python3 P150 allocated absolute inos
    aset = {(a[2] << 22) + a[3] + a[4] for a in pyalloc[n]}
    p87sel = [(ln, t, "P87-OPEN-CHECK", line) for ln, t, line in p87[n]
              if int(re.search(r'ino=(\d+)', line).group(1)) in aset]
    merged = sorted(items + p87sel, key=lambda x: x[0])
    print("\n=== B1. %s: comm=python3 events (P150-ALLOC-UI, P150-FREE-IBT, P145-ALLOC, ino+f0000NNN name; "
          "P87-OPEN-CHECK has no comm= field so it is included only when its ino is a python3 P150-ALLOC-UI inode)" % n)
    kc = collections.Counter(x[2] for x in merged)
    print("kind totals in whole log:", dict(kc), "total", len(merged))
    print("-- literal first %d in log order" % cap)
    for ln, t, kind, line in merged[:cap]:
        print("%s:%d: [%s] %s" % (n, ln, kind, line[:260]))
    late = [x for x in merged if x[1] is not None and x[1] >= THRESH]
    print("-- first %d with time >= THRESH (end-of-row run); %d such events before cap" % (cap, len(late)))
    for ln, t, kind, line in late[:cap]:
        print("%s:%d: [%s] %s" % (n, ln, kind, line[:260]))
    print("-- distinct ino= values in comm=python3 lines, first-seen order, first 40 of %d (ino count first-line)" % len(pyino[n]))
    for ino, (c, ln, line, t) in list(pyino[n].items())[:40]:
        print("  ino=%d count=%d first=%s:%d" % (ino, c, n, ln))

# ------------------------------------------------------------ C
print("\n=== C0. inode number formula check: absolute ino = (agno<<22) + agino")
print("P82-REM lines (all nodes): %d, ino == (agno<<22)+agino for %d; mismatches shown below" % (rem_total, rem_ok))
for n, ln, line in rem_bad:
    print("  BAD %s:%d: %s" % (n, ln, line[:300]))
# verbatim anchor: test11 ino 8920798
anchor = (2 << 22) + 532160 + 30
print("anchor: agno=2 startino=532160 off=30 -> (2<<22)+532190 = %d (0x%x)" % (anchor, 532190))
with open(path("test11"), "rb") as fh:
    for ln, raw in enumerate(fh, 1):
        line = raw.decode("latin-1").rstrip("\n")
        if ("ino=%d " % anchor in line and ("P87-OPEN-CHECK" in line or "P82-REM" in line)) or \
           ("agno=2 startino=532160 off=30 " in line and "P150-" in line):
            print("  test11:%d: %s" % (ln, line[:300]))


def sel_inos(n, k):
    out = []
    seen = set()
    for ln, t, agno, st, of, line in pyalloc[n]:
        if t is None or t < THRESH:
            continue
        ino = (agno << 22) + st + of
        out.append((ino, ln, agno, st, of))
        if len(out) == k:
            break
    return out


targets = {}
sel11 = sel_inos("test11", 16)
sel7 = sel_inos("test7", 6)
lit11 = [(a[2] << 22) + a[3] + a[4] for a in pyalloc["test11"][:16]]
print("\n=== C1. inode selection")
print("test11 python3 P150-ALLOC-UI total:", len(pyalloc["test11"]), "; literal first 16 (log order from start of log, uptime %s) abs inos: %s" % (
    pyalloc["test11"][0][5].split()[0] if pyalloc["test11"] else "-", lit11))
print("test11 first 16 python3 allocs with time>=THRESH (used for the grep): (abs_ino, line, agno, startino, off)")
for x in sel11:
    print("  ", x)
print("test7 python3 P150-ALLOC-UI total:", len(pyalloc["test7"]), "(none: test7's python3 inode allocations produce no P150 event; see B0)")
sub7 = []
if not sel7:
    skip = {6859, 6860}
    for ino, (c, ln, line, t) in pyino["test7"].items():
        if t is None or t < THRESH or ino in skip or ino == 0:
            continue
        sub7.append((ino, ln))
        if len(sub7) == 6:
            break
    print("SUBSTITUTE for test7 (NOT allocations): first 6 distinct ino= values first seen in comm=python3 lines at time>=THRESH, excluding 6859/6860/0:", sub7)
    sel7 = [(i, ln, None, None, None) for i, ln in sub7]
for n, lst in (("test11", sel11), ("test7", sel7)):
    for ino, ln, a, b, c in lst:
        targets[ino] = n
alt = re.compile(r'(?<![0-9])ino=(' + "|".join(str(i) for i in sorted(targets)) + r')(?![0-9])') if targets else None
hits = {i: {n: [] for n in nodes} for i in targets}
for n in nodes:
    off = None
    with open(path(n), "rb") as fh:
        for ln, raw in enumerate(fh, 1):
            line = raw.decode("latin-1").rstrip("\n")
            s = stamp.match(line)
            up = float(s.group(1)) * 1e9 if s else None
            r = realre.search(line)
            if r:
                t = int(r.group(1))
                if up is not None:
                    off = t - up
            elif up is not None and off is not None:
                t = int(up + off)
            else:
                t = None
            if "ino=" not in line:
                continue
            for m in alt.finditer(line):
                hits[int(m.group(1))][n].append((ln, t, line))


def report(owner, lst, label):
    print("\n=== C2. %s" % label)
    for ino, ln, a, b, c in lst:
        h = hits[ino]
        print("\n-- ino=%d (owner %s, from %s:%d%s)" % (ino, owner, owner, ln, "" if a is None else " agno=%d startino=%d off=%d" % (a, b, c)))
        print("   count per node (all log / time>=THRESH): " + ", ".join(
            "%s %d/%d" % (n, len(h[n]), sum(1 for x in h[n] if x[1] is not None and x[1] >= THRESH)) for n in nodes))
        other = sorted([(n, x) for n in nodes if n != owner for x in h[n]], key=lambda z: (z[1][1] if z[1][1] is not None else 0))
        print("   lines from nodes other than %s: %d before cap; first 12 in time order:" % (owner, len(other)))
        for n, (l2, t, line) in other[:12]:
            print("   %s:%d: %s" % (n, l2, line[:300]))
        late = [z for z in other if z[1][1] is not None and z[1][1] >= THRESH]
        print("   of those, with time>=THRESH: %d; first 12:" % len(late))
        for n, (l2, t, line) in late[:12]:
            print("   %s:%d: %s" % (n, l2, line[:300]))


report("test11", sel11, "test11 first 16 python3 allocations at/after THRESH; other nodes' lines")
report("test7", sel7, "test7 first 6 python3 inodes (%s); other nodes' lines" % ("P150 allocations" if pyalloc["test7"] else "SUBSTITUTE: not allocations"))
