#!/usr/bin/env python3
"""matrix_check.py — verify a condition's criteria matrix is 100% PASS,
optionally requiring every cell to have been recorded at/after a given epoch
(so passes from older builds can't silently satisfy a re-validation).

Conditions (conditions.md / run.sh <dlm> axis):
    tcp  = TCP DLM / commodity block (LIO)      cawp = CAW FC-sim passthrough
    cawd = CAW direct in-guest iSCSI            caw  = CAW over dm-multipath

Usage:
    scripts/matrix_check.py [--cond caw|cawd|cawp|tcp|all]
                            [--since ISO8601] [--nodes 1,2,4,8,16,32]

Exit 0 iff every applicable (test, N/<cond>) cell is PASS (and fresh if
--since), across every requested condition.  Prints a per-N summary per
condition plus every violation.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

CONDITIONS = ("tcp", "cawp", "cawd", "caw")


def parse_iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def base_transport(cond):
    return "caw" if cond in ("cawd", "cawp") else cond


def check_cond(d, cond, nodes, since, since_raw):
    """Return (per_n, bad) for one condition column."""
    base = base_transport(cond)
    bad = []
    per_n = {}
    for c in d["categories"]:
        tr = c.get("transport", "any")
        if tr not in ("any", base):
            continue
        for t in c["tests"]:
            name, mn, mx = t["name"], t.get("min_nodes", 1), t.get("max_nodes", 0)
            for n in nodes:
                if n < mn or (mx and n > mx):
                    continue
                cell = t["runs"].get(f"{n}/{cond}")
                per_n.setdefault(n, [0, 0])
                per_n[n][1] += 1
                if not cell:
                    bad.append(f"{n}/{cond} {name}: UNRUN")
                    continue
                if cell["status"] != "PASS":
                    # SKIP is a violation too: the accepted green-ladder
                    # standard is "0 FAIL, 0 SKIPPED, 0 PENDING" per cell
                    # (xfs-baseline rows, where SKIP is legitimate, live in
                    # the N/xfs column which is never checked here).
                    bad.append(f"{n}/{cond} {name}: {cell['status']} ({cell.get('reason','')[:80]})")
                    continue
                if since and parse_iso(cell["iso"]) < since:
                    bad.append(f"{n}/{cond} {name}: STALE (iso {cell['iso']} < {since_raw})")
                    continue
                per_n[n][0] += 1
    return per_n, bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cond", default="caw",
                    help="condition column to check: tcp|cawp|cawd|caw|all")
    ap.add_argument("--since", help="require cell iso >= this (ISO8601)")
    ap.add_argument("--nodes", default="1,2,4,8,16,32")
    ap.add_argument("--criteria", default="criteria.json")
    args = ap.parse_args()

    since = parse_iso(args.since) if args.since else None
    nodes = [int(x) for x in args.nodes.split(",")]
    conds = CONDITIONS if args.cond == "all" else (args.cond,)
    for c in conds:
        if c not in CONDITIONS:
            sys.exit(f"unknown condition '{c}' (expect tcp|cawp|cawd|caw|all)")
    d = json.load(open(args.criteria))

    all_bad = []
    for cond in conds:
        per_n, bad = check_cond(d, cond, nodes, since, args.since)
        all_bad.extend(bad)
        for n in nodes:
            ok, tot = per_n.get(n, (0, 0))
            print(f"{n}/{cond}: {ok}/{tot} PASS{' (fresh)' if since else ''}")
    if all_bad:
        print("\nVIOLATIONS:")
        for b in all_bad:
            print(" ", b)
        sys.exit(1)
    scope = "ALL 4 CONDITIONS" if args.cond == "all" else args.cond
    print(f"\nMATRIX 100% PASS [{scope}]" + (f" (all cells >= {args.since})" if since else ""))
    sys.exit(0)


if __name__ == "__main__":
    main()
