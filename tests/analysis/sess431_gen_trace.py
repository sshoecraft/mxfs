#!/usr/bin/env python3
"""sess431 s439: trace generation numbers of FREE-FOREIGN specimens across all 32 node logs.

Usage: python3 sess431_gen_trace.py <rawdir> <outdir>
Pass 1: specimen gen_home / gen_home+1 occurrences, per-ino tag counts, FOREIGN inventory.
Pass 2: for every FOREIGN disk_gen, find occurrences OUTSIDE FOREIGN/P383/DISKLIVE/P218 lines.
"""
import os, re, sys, json
from collections import defaultdict

RAW = sys.argv[1]
OUT = sys.argv[2]
os.makedirs(OUT, exist_ok=True)
NODES = ["test%d" % i for i in range(1, 33)]

SPECIMENS = [
    ("S1", "test1",  "134",      2204568790, 4273869622),
    ("S2", "test1",  "135",      1956418829, 3985103989),
    ("S3", "test1",  "136",      3960562887, 3202048607),
    ("S4", "test1",  "138",      20556183,   972460776),
    ("S5", "test19", "20971651", 49656385,   1347893606),
]

TAGS = ["P-FREEPUB-CLAIM", "P55C-FREE-FLUSH", "P55C-FREE-HOME",
        "P55C-FREE-FOREIGN", "P-DIALLOC-DISKLIVE"]

# --- pass 1 patterns -------------------------------------------------------
p1_nums = {}
for lab, _, _, gh, _ in SPECIMENS:
    p1_nums[gh] = (lab, "gen_home")
    p1_nums[gh + 1] = (lab, "gen_home+1")
p1_re = re.compile(r"=(" + "|".join(str(n) for n in sorted(p1_nums)) + r")(?![0-9])")

ino_re = {}
for lab, _, ino, _, _ in SPECIMENS:
    ino_re[lab] = [(t, t + " ino=" + ino + " ") for t in TAGS]

FOREIGN_RE = re.compile(
    r"P55C-FREE-FOREIGN ino=(\d+) gen=(\d+) disk_gen=(\d+)")

hits = defaultdict(list)                 # (lab, kind) -> [(node, lineno, line)]
tagcount = defaultdict(int)              # (lab, node, tag) -> n
foreign = []                             # (node, lineno, ino, gen, disk_gen, line)
foreign_per_node = defaultdict(int)

for node in NODES:
    path = os.path.join(RAW, node + ".log")
    with open(path, "r", errors="replace") as f:
        for lno, line in enumerate(f, 1):
            if "P55C-FREE-FOREIGN" in line:
                foreign_per_node[node] += 1
                m = FOREIGN_RE.search(line)
                if m:
                    foreign.append((node, lno, m.group(1), m.group(2),
                                    m.group(3), line.rstrip("\n")))
            for m in p1_re.finditer(line):
                lab, kind = p1_nums[int(m.group(1))]
                hits[(lab, kind)].append((node, lno, line.rstrip("\n")))
            for lab, pats in ino_re.items():
                for tag, needle in pats:
                    if needle in line:
                        tagcount[(lab, node, tag)] += 1

json.dump({"%s|%s" % k: v for k, v in hits.items()},
          open(os.path.join(OUT, "pass1_hits.json"), "w"), indent=1)
json.dump({"%s|%s|%s" % k: v for k, v in tagcount.items()},
          open(os.path.join(OUT, "pass1_tagcount.json"), "w"), indent=1)
json.dump({"foreign": foreign, "per_node": foreign_per_node},
          open(os.path.join(OUT, "pass1_foreign.json"), "w"), indent=1)

# --- pass 2: FOREIGN disk_gen values seen elsewhere ------------------------
EXCL = ("P55C-FREE-FOREIGN", "P383", "P-DIALLOC-DISKLIVE", "P218")
dgens = sorted({int(f[4]) for f in foreign})
p2_re = re.compile(r"=(" + "|".join(str(n) for n in dgens) + r")(?![0-9])")
elsewhere = defaultdict(list)
for node in NODES:
    path = os.path.join(RAW, node + ".log")
    with open(path, "r", errors="replace") as f:
        for lno, line in enumerate(f, 1):
            if any(e in line for e in EXCL):
                continue
            for m in p2_re.finditer(line):
                elsewhere[int(m.group(1))].append((node, lno, line.rstrip("\n")))
json.dump({str(k): v for k, v in elsewhere.items()},
          open(os.path.join(OUT, "pass2_elsewhere.json"), "w"), indent=1)
print("dgens=%d distinct, foreign_lines=%d, dgens_seen_elsewhere=%d"
      % (len(dgens), len(foreign), len(elsewhere)))
