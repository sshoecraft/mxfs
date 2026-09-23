#!/usr/bin/env python3
"""
Correlate P-DIALLOC-DISKLIVE lines against preceding P55C-FREE-FLUSH/CHAIN
lines (any node), and check for P-CLMERGE restored / P239-OVERLAY-ID /
P56-NL-LOGGED-DIR-SKIP within 2s after that P55C line on the SAME node
the P55C line was found on.

Usage: python3 analyze_p_diskslive_p55c.py <evidence_dir>
"""
import sys, re, glob, os

EVDIR = sys.argv[1] if len(sys.argv) > 1 else "."
RAWDIR = os.path.join(EVDIR, "raw")
DISKLIVE_FILE = os.path.join(EVDIR, "all_diskslive_lines.txt")

TS_RE = re.compile(r'^\[\s*([0-9.]+)\]\s+(\S+)\s+kernel:\s+mxfs:\s+(.*)$')

def parse_line(line):
    m = TS_RE.match(line.rstrip("\n"))
    if not m:
        return None
    t = float(m.group(1))
    node = m.group(2)
    rest = m.group(3)
    return t, node, rest

# ---- load raw logs per node, extract events of interest ----
# per node: list of (t, kind, ino, raw_line) for P55C-FREE-FLUSH/CHAIN
# per node: list of (t, ino, bmode, dmode) for P-CLMERGE restored
# per node: list of (t, ino, arm) for P239-OVERLAY-ID
# per node: list of (t, ino) for P56-NL-LOGGED-DIR-SKIP

p55c = {}      # node -> list of (t, kind, ino)
clmerge = {}   # node -> list of (t, ino, bmode, dmode)
p239 = {}      # node -> list of (t, ino, arm)
p56 = {}       # node -> list of (t, ino)

ino_re = re.compile(r'\bino=(\d+)\b')
bmode_re = re.compile(r'\bbmode=(\S+)\b')
dmode_re = re.compile(r'\bdmode=(\S+)\b')
arm_re = re.compile(r'\barm=(\S+)\b')

raw_files = sorted(glob.glob(os.path.join(RAWDIR, "*.log")))
malformed_count = 0
total_lines_scanned = 0

# sess431: the '[ secs]' stamp is each VM's OWN monotonic clock — NOT comparable
# across nodes (the first run of this script ordered cross-node events on raw
# stamps and mis-reported 34 "no preceding P55C" events; 3 of 6 checked had one
# in wall-clock).  Every node prints NTP wall-clock ms in 'realms=' (P291-EXWIN
# and others); the per-node median of (realms/1000 - t) converts a node's
# stamps to wall-clock.  All comparisons below are in WALL seconds.
realms_re = re.compile(r'\brealms=(\d+)\b')
node_offset = {}   # node -> wall - mono (s)
offset_samples = {}

for rf in raw_files:
    node_from_fname = os.path.basename(rf)[:-4]  # testN
    p55c.setdefault(node_from_fname, [])
    clmerge.setdefault(node_from_fname, [])
    p239.setdefault(node_from_fname, [])
    p56.setdefault(node_from_fname, [])
    offset_samples.setdefault(node_from_fname, [])
    with open(rf, "r", errors="replace") as f:
        for line in f:
            if "realms=" in line:
                pr = parse_line(line)
                mr = realms_re.search(line)
                if pr and mr:
                    offset_samples[node_from_fname].append(int(mr.group(1)) / 1000.0 - pr[0])
            if "P55C-FREE-FLUSH" not in line and "P55C-FREE-CHAIN" not in line \
               and "P-CLMERGE restored" not in line and "P239-OVERLAY-ID" not in line \
               and "P56-NL-LOGGED-DIR-SKIP" not in line:
                continue
            total_lines_scanned += 1
            parsed = parse_line(line)
            if parsed is None:
                malformed_count += 1
                continue
            t, node, rest = parsed
            m_ino = ino_re.search(rest)
            if not m_ino:
                malformed_count += 1
                continue
            ino = int(m_ino.group(1))
            if "P55C-FREE-FLUSH" in rest:
                p55c[node].append((t, "FLUSH", ino))
            elif "P55C-FREE-CHAIN" in rest:
                p55c[node].append((t, "CHAIN", ino))
            elif "P-CLMERGE restored" in rest:
                mb = bmode_re.search(rest); md = dmode_re.search(rest)
                clmerge[node].append((t, ino, mb.group(1) if mb else "?", md.group(1) if md else "?"))
            elif "P239-OVERLAY-ID" in rest:
                ma = arm_re.search(rest)
                p239[node].append((t, ino, ma.group(1) if ma else "?"))
            elif "P56-NL-LOGGED-DIR-SKIP" in rest:
                p56[node].append((t, ino))

nodes_without_offset = []
for node, samples in offset_samples.items():
    if samples:
        samples.sort()
        node_offset[node] = samples[len(samples) // 2]
    else:
        node_offset[node] = 0.0
        nodes_without_offset.append(node)

def to_wall(node, t):
    return t + node_offset.get(node, 0.0)

for d in (p55c, clmerge, p239, p56):
    for k in d:
        d[k] = [(to_wall(k, e[0]),) + tuple(e[1:]) for e in d[k]]
        d[k].sort(key=lambda x: x[0])

# ---- load the 123 P-DIALLOC-DISKLIVE lines ----
disklive_events = []
disklive_malformed = 0
with open(DISKLIVE_FILE, "r", errors="replace") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        parsed = parse_line(line)
        if parsed is None:
            disklive_malformed += 1
            continue
        t, node, rest = parsed
        m_ino = ino_re.search(rest)
        if not m_ino:
            disklive_malformed += 1
            continue
        ino = int(m_ino.group(1))
        disklive_events.append((node, ino, to_wall(node, t), line))

results = []
no_p55c_any_node = []

for node, ino, T, raw in disklive_events:
    # search ALL nodes' P55C lists for matching ino, t < T; take latest (max t)
    best = None  # (t, kind, node)
    for pnode, evs in p55c.items():
        for (t, kind, pino) in evs:
            if pino == ino and t < T:
                if best is None or t > best[0]:
                    best = (t, kind, pnode)
    if best is None:
        no_p55c_any_node.append((node, ino, T))
        results.append(dict(node=node, ino=ino, T=T, p55c_node=None, p55c_kind=None,
                             p55c_t=None, clmerge=None, p239_arm=None, p56skip=False))
        continue
    p55c_t, p55c_kind, p55c_node = best
    window_lo, window_hi = p55c_t, p55c_t + 2.0

    # P-CLMERGE restored on p55c_node, ino match, within (p55c_t, p55c_t+2]
    cl_hit = None
    for (t, cino, bmode, dmode) in clmerge.get(p55c_node, []):
        if cino == ino and window_lo < t <= window_hi:
            cl_hit = (t, bmode, dmode)
            break  # first one in window

    # P239-OVERLAY-ID on p55c_node, ino match, within window
    p239_hit = None
    for (t, pino, arm) in p239.get(p55c_node, []):
        if pino == ino and window_lo < t <= window_hi:
            p239_hit = (t, arm)
            break

    # P56-NL-LOGGED-DIR-SKIP on p55c_node, ino match, within window
    p56_hit = False
    for (t, pino) in p56.get(p55c_node, []):
        if pino == ino and window_lo < t <= window_hi:
            p56_hit = True
            break

    results.append(dict(node=node, ino=ino, T=T, p55c_node=p55c_node, p55c_kind=p55c_kind,
                         p55c_t=p55c_t, clmerge=cl_hit, p239_arm=(p239_hit[1] if p239_hit else None),
                         p56skip=p56_hit))

# ---- output table ----
print("wall-clock offsets (s, wall - node monotonic): " +
      " ".join(f"{n}={node_offset[n]:.3f}" for n in sorted(node_offset, key=lambda s: int(s[4:]) if s[4:].isdigit() else 0)))
if nodes_without_offset:
    print("WARNING nodes with NO realms= sample (offset 0, cross-node order unreliable): " + " ".join(nodes_without_offset))
hdr = f"{'node':<7} {'ino':<11} {'T(wall)':<16} {'P55C_node':<10} {'P55C_kind':<6} {'P55C_t(wall)':<16} {'clmerge(bmode,dmode)':<24} {'p239_arm':<10} {'p56skip':<7}"
print(hdr)
print("-" * len(hdr))
for r in results:
    cl = f"({r['clmerge'][1]},{r['clmerge'][2]})" if r['clmerge'] else "-"
    p55c_node_s = r['p55c_node'] or "NONE"
    p55c_kind_s = r['p55c_kind'] or "-"
    p55c_t_s = f"{r['p55c_t']:.3f}" if r['p55c_t'] is not None else "-"
    p239_s = r['p239_arm'] or "-"
    print(f"{r['node']:<7} {r['ino']:<11} {r['T']:<16.3f} {p55c_node_s:<10} {p55c_kind_s:<6} {p55c_t_s:<16} {cl:<24} {p239_s:<10} {str(r['p56skip']):<7}")

print()
print("=== SUMMARY ===")
total = len(results)
have_p55c = [r for r in results if r['p55c_node'] is not None]
have_clmerge_bmode00 = [r for r in have_p55c if r['clmerge'] and r['clmerge'][1] == '00']
have_p56skip = [r for r in have_p55c if r['p56skip']]

print(f"Total P-DIALLOC-DISKLIVE lines processed: {total} (source file lines: {len(disklive_events)}, malformed/skipped from source: {disklive_malformed})")
print(f"Have a preceding P55C-FREE-FLUSH/CHAIN on SOME node (any node) before T: {len(have_p55c)} of {total}")
print(f"  ...of those, have a P-CLMERGE restored with bmode=00 within 2s after P55C on the P55C node: {len(have_clmerge_bmode00)} of {len(have_p55c)}")
print(f"  ...of those, have a P56-NL-LOGGED-DIR-SKIP within 2s after P55C on the P55C node: {len(have_p56skip)} of {len(have_p55c)}")
print(f"NO preceding P55C-FREE-FLUSH/CHAIN found on ANY node before T: {len(no_p55c_any_node)} of {total}")
if no_p55c_any_node:
    print("  inos with no preceding P55C on any node:")
    for (node, ino, T) in no_p55c_any_node:
        print(f"    node={node} ino={ino} T={T:.6f}")

print()
print(f"[diag] raw log files scanned: {len(raw_files)}; event lines matched (pre-parse filter): {total_lines_scanned}; malformed/unparsed event lines skipped: {malformed_count}")
