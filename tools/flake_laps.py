#!/usr/bin/env python3
"""How many more runs each FLAKY cell of the board needs before it reads PASS.

A cell reads FLAKY while a genuine FAIL sits in its 11-run window
(tools/criteria.py flake_count: a FAIL whose reason is not rig noise and that
carries no detector-defect amendment).  With the newest such FAIL at window
index k (0 = the live run), the cell needs 11-k further runs of that row, and
the board run that follows the laps is one of them.

Read-only.  Usage: tools/flake_laps.py [<configuration> ...]   (default: every
configuration that has a cell with a genuine FAIL in its window)
Prints: <configuration> <row> k=<k> window=<n> more_runs=<11-k> laps_before_board=<10-k>
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import criteria  # noqa: E402  (the board's own constants and noise pattern)


def main():
    want = set(sys.argv[1:])
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "criteria.json")
    board = json.load(open(path))
    rows = board["criteria"] if isinstance(board, dict) else board
    for c in rows:
        for cfg, cell in sorted((c.get("per_config") or {}).items()):
            if want and cfg not in want:
                continue
            runs = ([cell] + list(cell.get("history") or []))[:criteria.FLAKE_WINDOW]
            ks = [i for i, r in enumerate(runs)
                  if str(r.get("status", "")).upper().strip() == "FAIL"
                  and not criteria.RIG_NOISE.search(str(r.get("reason", "")))
                  and not r.get("detector_defect")]
            if not ks:
                continue
            k = ks[0]
            print(f"{cfg} {c.get('id')} k={k} window={len(runs)} "
                  f"more_runs={criteria.FLAKE_WINDOW - k} laps_before_board={criteria.FLAKE_WINDOW - 1 - k} "
                  f"live={cell.get('status')}")


if __name__ == "__main__":
    main()
