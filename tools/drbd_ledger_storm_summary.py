#!/usr/bin/env python3
"""drbd_ledger_storm_summary.py — one line per leg of tests/drbd_ledger_storm_ab.sh,
so legs of an A/B can be set side by side.

From walk.out: the seed's create p50/p90, the first cold walk's wall, the
touch's wall, the second walk's wall.  From the profile snapshots: the RELEASE
STORM, i.e. the snapshot intervals in which participant 1 (the second node of
PVE_PAIR) released 100 or more grants (mxfs_dlm_unlock_open), with participant
1's ledger commits in them (dlm_txn_commit calls and mean wall), its flushes
per commit, its lock acquisitions' mean wall (dlm_lock_impl) and stat mean wall
(xfs_vn_getattr) — the walk that runs beside the storm.

Usage: tools/drbd_ledger_storm_summary.py EVID_DIR [EVID_DIR ...]
"""
import collections
import glob
import os
import re
import sys

UNIT = {"ns": 1e-6, "us": 1e-3, "ms": 1.0, "s": 1e3}
ROW = re.compile(r"^\s*(\S+)\s+(\d+)\s+([\d.]+)\s+(ns|us|ms|s)\b")


def load(path):
    hits, tot = collections.Counter(), collections.Counter()
    with open(path, errors="replace") as f:
        for line in f:
            m = ROW.match(line)
            if not m or m.group(1) == "Function":
                continue
            hits[m.group(1)] += int(m.group(2))
            tot[m.group(1)] += float(m.group(3)) * UNIT[m.group(4)]
    return hits, tot


def walk_numbers(evid):
    out = {}
    text = open(os.path.join(evid, "walk.out"), errors="replace").read()
    m = re.search(r"create\s+n=\d+ p50=([\d.]+) ms p90=([\d.]+) ms", text)
    if m:
        out["create_p50"], out["create_p90"] = float(m.group(1)), float(m.group(2))
    walls = re.findall(r"-p1 \S+: entries=\d+ wall=(\d+) ms", text)
    if walls:
        out["walk1_ms"] = int(walls[0])
    if len(walls) > 1:
        out["walk2_ms"] = int(walls[1])
    m = re.search(r"TOUCH_MS=(\d+)", text)
    if m:
        out["touch_ms"] = int(m.group(1))
    return out


def storm_numbers(evid, host):
    snaps = sorted(glob.glob(os.path.join(evid, "profile", f"{host}.profile.*")),
                   key=lambda p: int(p.rsplit(".", 1)[1]))
    acc = collections.Counter()
    for a, b in zip(snaps, snaps[1:]):
        h0, t0 = load(a)
        h1, t1 = load(b)
        if h1["mxfs_dlm_unlock_open"] - h0["mxfs_dlm_unlock_open"] < 100:
            continue
        for fn in ("dlm_txn_commit", "mxfs_pal_bdev_flush", "dlm_lock_impl", "xfs_vn_getattr",
                   "mxfs_tauth_page_write_many"):
            acc[fn + ".n"] += h1[fn] - h0[fn]
            acc[fn + ".ms"] += t1[fn] - t0[fn]
        acc["intervals"] += 1
    return acc


def main():
    for evid in sys.argv[1:]:
        w = walk_numbers(evid)
        hosts = sorted({os.path.basename(p).split(".")[0]
                        for p in glob.glob(os.path.join(evid, "profile", "*.profile.*"))})
        line = [os.path.basename(evid.rstrip("/"))]
        line += [f"{k}={w[k]}" for k in ("create_p50", "create_p90", "walk1_ms", "touch_ms", "walk2_ms") if k in w]
        for h in hosts:
            s = storm_numbers(evid, h)
            if not s["intervals"]:
                continue
            n = s["dlm_txn_commit.n"]
            line.append(f"{h}: storm_intervals={s['intervals']} commits={n} "
                        f"commit_mean_ms={s['dlm_txn_commit.ms'] / max(n, 1):.1f} "
                        f"flush_per_commit={s['mxfs_pal_bdev_flush.n'] / max(n, 1):.2f} "
                        f"batches={s['mxfs_tauth_page_write_many.n']} "
                        f"lock_mean_ms={s['dlm_lock_impl.ms'] / max(s['dlm_lock_impl.n'], 1):.1f} "
                        f"stat_n={s['xfs_vn_getattr.n']} "
                        f"stat_mean_ms={s['xfs_vn_getattr.ms'] / max(s['xfs_vn_getattr.n'], 1):.1f}")
        print("  ".join(line))


if __name__ == "__main__":
    main()
