#!/usr/bin/env python3
"""Census extractor for D-DIR-LEAF-HASH-INDEX-LOSES-ENTRIES-MASKED-BY-DATASCAN-HEAL-0496.

Scans kernlog_test*.gz under tests/evidence/run_*<DAY>T*/ and counts the
instrumentation markers relevant to the dir-fence / datascan-heal interaction.
Counts only; never prints raw log lines.
"""
import glob, os, re, subprocess, sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor

EVID = "/src/mxfs/tests/evidence"
DAY = sys.argv[1] if len(sys.argv) > 1 else "20260904"
MARKERS = ["P123-DIRFENCE-SKIP", "P-FENCE-AILLEAK", "P22-DATASCAN-HIT",
           "P287-F4-SUPPRESSED-COMPLETION", "P285-F4-CENSUS"]
GREP = "|".join(MARKERS)
KV = re.compile(r'(\w+)=("[^"]*"|\S+)')

def scan(path):
    p = subprocess.run(["bash", "-c", f"zcat -f {path!r} | grep -E {GREP!r} || true"],
                       capture_output=True, text=True, errors="replace")
    res = {"skip_fmt": Counter(), "skip_drain": Counter(), "ailleak_fmt": Counter(),
           "datascan": 0, "f4supp": 0, "f4census": 0, "ds_ino": Counter(),
           "d1_fmt": Counter(), "d1_bli": Counter(), "d1_done": Counter(),
           "d1_seqdiff": 0, "d1_total": 0,
           "owner_dir": Counter(), "owner_blk": Counter()}
    for line in p.stdout.splitlines():
        if "P123-DIRFENCE-SKIP" in line:
            f = dict(KV.findall(line))
            fmt = f.get("fmt", "?"); dr = f.get("in_drain", "?")
            res["skip_fmt"][fmt] += 1
            res["skip_drain"][dr] += 1
            own = f.get("owner", "?")
            if fmt in ("leaf1", "leafn", "danode", "free"):
                res["owner_dir"][own] += 1
            elif fmt in ("block", "data"):
                res["owner_blk"][own] += 1
            if dr == "1":
                res["d1_total"] += 1
                res["d1_fmt"][fmt] += 1
                res["d1_bli"][f.get("has_bli", "?")] += 1
                res["d1_done"][f.get("done", "?")] += 1
                if f.get("lseq") != f.get("wseq"):
                    res["d1_seqdiff"] += 1
        elif "P-FENCE-AILLEAK" in line:
            res["ailleak_fmt"][dict(KV.findall(line)).get("fmt", "?")] += 1
        elif "P22-DATASCAN-HIT" in line:
            res["datascan"] += 1
            res["ds_ino"][dict(KV.findall(line)).get("ino", "?")] += 1
        elif "P287-F4-SUPPRESSED-COMPLETION" in line:
            res["f4supp"] += 1
        elif "P285-F4-CENSUS" in line:
            res["f4census"] += 1
    return path, res

def merge(dst, src):
    for k, v in src.items():
        if isinstance(v, Counter): dst[k].update(v)
        else: dst[k] = dst.get(k, 0) + v

def blank():
    return defaultdict(Counter, {"datascan": 0, "f4supp": 0, "f4census": 0,
                                 "d1_seqdiff": 0, "d1_total": 0})

runs = sorted(glob.glob(f"{EVID}/run_*{DAY}T*/"), key=lambda d: (re.search(r'(\d{8}T\d{6})', d).group(1), d))
files = [f for r in runs for f in sorted(glob.glob(r + "kernlog_test*.gz"))]
print(f"# run dirs: {len(runs)}   files scanned: {len(files)}")

per_run = {r: blank() for r in runs}
total = blank()
with ProcessPoolExecutor(max_workers=32) as ex:
    for path, res in ex.map(scan, files, chunksize=4):
        r = os.path.dirname(path) + "/"
        merge(per_run[r], res); merge(total, res)

FMTS = ["block", "data", "leaf1", "leafn", "free", "danode"]
print("\n## 1. PER RUN  (blk/data/lf1/lfn/free/dano | drain0/drain1 | AILLEAK | DS | F4SUP | F4CEN)")
hdr = f"{'run(UTC time)':<16}" + "".join(f"{f[:5]:>7}" for f in FMTS) + f"{'dr0':>8}{'dr1':>7}{'ALEAK':>7}{'DS':>6}{'F4SUP':>7}{'F4CEN':>7}"
print(hdr)
for r in runs:
    d = per_run[r]
    if not (sum(d["skip_fmt"].values()) or d["datascan"] or d["f4supp"] or d["f4census"] or sum(d["ailleak_fmt"].values())):
        continue
    tag = re.search(r'(\d{8}T\d{6})', r).group(1)[9:]
    nm = ("cc" if "crash_consistency" in r else "dr") + "-" + tag
    print(f"{nm:<16}" + "".join(f"{d['skip_fmt'][f]:>7}" for f in FMTS)
          + f"{d['skip_drain']['0']:>8}{d['skip_drain']['1']:>7}"
          + f"{sum(d['ailleak_fmt'].values()):>7}{d['datascan']:>6}{d['f4supp']:>7}{d['f4census']:>7}")
print("(run dirs with all-zero counts omitted; see totals for full set)")
zero = [r for r in runs if not (sum(per_run[r]["skip_fmt"].values()) or per_run[r]["datascan"]
        or per_run[r]["f4supp"] or per_run[r]["f4census"] or sum(per_run[r]["ailleak_fmt"].values()))]
print(f"all-zero run dirs: {len(zero)}")

print(f"\n## 2. in_drain=1 P123-DIRFENCE-SKIP  (total {total['d1_total']})")
print("  fmt     :", dict(total["d1_fmt"]))
print("  has_bli :", dict(total["d1_bli"]))
print("  done    :", dict(total["d1_done"]))
print(f"  lseq!=wseq: {total['d1_seqdiff']} of {total['d1_total']}")

print("\n## 3. RUNS WITH P22-DATASCAN-HIT  -> ino, dir-fmt skips, blk-fmt skips")
print(f"{'run':<16}{'ino':>12}{'hits':>7}{'skip(leaf1/leafn/danode/free)':>32}{'skip(block/data)':>19}")
any_ds = False
for r in runs:
    d = per_run[r]
    if not d["datascan"]: continue
    any_ds = True
    tag = re.search(r'(\d{8}T\d{6})', r).group(1)[9:]
    nm = ("cc" if "crash_consistency" in r else "dr") + "-" + tag
    for ino, n in sorted(d["ds_ino"].items(), key=lambda x: -x[1]):
        print(f"{nm:<16}{ino:>12}{n:>7}{d['owner_dir'][ino]:>32}{d['owner_blk'][ino]:>19}")
        nm = ""
if not any_ds: print("  (none)")

print("\n## 4. DAY TOTALS")
print("  P123-DIRFENCE-SKIP by fmt   :", dict(total["skip_fmt"]), "sum=", sum(total["skip_fmt"].values()))
print("  P123-DIRFENCE-SKIP by drain :", dict(total["skip_drain"]))
print("  P-FENCE-AILLEAK by fmt      :", dict(total["ailleak_fmt"]), "sum=", sum(total["ailleak_fmt"].values()))
print("  P22-DATASCAN-HIT            :", total["datascan"], " distinct ino:", len(total["ds_ino"]))
print("  P287-F4-SUPPRESSED-COMPLETION:", total["f4supp"])
print("  P285-F4-CENSUS              :", total["f4census"])
