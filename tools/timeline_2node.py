#!/usr/bin/env python3
"""Merge two nodes' harness dmesg captures into one timeline.

Each capture is the node's kernel log after the lap marker, lines shaped
"[ts] mxfs: TAG ...", and many probe lines carry a wall-clock stamp
"realns=N".  For each node the tool fits kernel time to wall time from the
realns-bearing lines (median of realns - ts), converts every line of that
node to wall time, and prints both nodes' lines interleaved, relative to an
anchor line matched on one node.  The two wall clocks are not perfectly in
step (the VMs have drifted ~20 ms apart in the past); --skew-ms shifts the
second node by that much once you have paired a causal send/receive.

    tools/timeline_2node.py <evidence_dir> <nodeA> <nodeB> \
        --anchor-node test2 --anchor 'comm=truncate' [--nth 1] \
        --before-ms 5 --after-ms 170 [--exclude P71-HOLD,P218,P56,P170] \
        [--skew-ms 0] [--grep 'ino=132|ag=']
"""
import argparse
import os
import re
import statistics
import sys

LINE = re.compile(r"^\[\s*(\d+\.\d+)\]\s*(.*)$")
REALNS = re.compile(r"realns=(\d+)")


def load(path):
    rows = []
    with open(path, errors="replace") as f:
        for raw in f:
            m = LINE.match(raw.rstrip("\n"))
            if not m:
                continue
            ts = float(m.group(1))
            text = m.group(2)
            r = REALNS.search(text)
            rows.append((ts, int(r.group(1)) if r else None, text))
    return rows


def fit_offset(rows):
    deltas = [realns / 1e9 - ts for ts, realns, _ in rows if realns]
    if not deltas:
        sys.exit("no realns-bearing lines to fit the clock from")
    return statistics.median(deltas)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence_dir")
    ap.add_argument("node_a")
    ap.add_argument("node_b")
    ap.add_argument("--anchor-node", required=True)
    ap.add_argument("--anchor", required=True, help="regex on the line text")
    ap.add_argument("--nth", type=int, default=1, help="use the nth match")
    ap.add_argument("--before-ms", type=float, default=5)
    ap.add_argument("--after-ms", type=float, default=170)
    ap.add_argument("--exclude", default="P71-HOLD,P218,P56,P170,P2D-DRAINWHY")
    ap.add_argument("--skew-ms", type=float, default=0,
                    help="add this to node_b's wall time")
    ap.add_argument("--grep", default=None, help="keep only lines matching")
    ap.add_argument("--width", type=int, default=230)
    args = ap.parse_args()

    nodes = {}
    for n in (args.node_a, args.node_b):
        rows = load(os.path.join(args.evidence_dir, f"dmesg_full_{n}.txt"))
        off = fit_offset(rows)
        nodes[n] = (rows, off)
        print(f"# {n}: {len(rows)} lines, wall = ts + {off:.6f} s")

    rows, off = nodes[args.anchor_node]
    pat = re.compile(args.anchor)
    hits = [ts for ts, _, text in rows if pat.search(text)]
    if len(hits) < args.nth:
        sys.exit(f"anchor matched {len(hits)} times, wanted {args.nth}")
    t0 = hits[args.nth - 1] + off
    if args.anchor_node == args.node_b:
        t0 += args.skew_ms / 1000
    print(f"# anchor wall {t0:.6f} ({args.anchor!r} #{args.nth} on {args.anchor_node})")

    excl = [e for e in args.exclude.split(",") if e]
    keep = re.compile(args.grep) if args.grep else None
    merged = []
    for n, (rows, off) in nodes.items():
        skew = args.skew_ms / 1000 if n == args.node_b else 0
        for ts, _, text in rows:
            w = ts + off + skew
            rel = (w - t0) * 1000
            if rel < -args.before_ms or rel > args.after_ms:
                continue
            if any(e in text for e in excl):
                continue
            if keep and not keep.search(text):
                continue
            merged.append((rel, n, ts, text))
    merged.sort()
    for rel, n, ts, text in merged:
        print(f"{rel:+9.3f} {n:6s} [{ts:.6f}] {text[:args.width]}")


if __name__ == "__main__":
    main()
