#!/usr/bin/env python3
"""How many more clean runs each board row needs before it reads PASS.

Usage: tools/criteria_window.py NODES DLM [--build SRCVERSION]

tools/criteria.py grades a row FLAKY while a genuine FAIL sits anywhere in its
11-run window (the live cell plus ten history entries).  A row whose newest
genuine FAIL is at window index k (0 = the live cell) reads PASS again after
11-k more runs of that row.  The board run that closes a verification is one
of them, so 10-k single-row laps are owed BEFORE that board run.

One line per row that is not clean, then the largest number of laps owed:

    ROW <id> status=<live status> newest_fail=<k> runs_needed=<11-k> laps_before_board=<10-k> [build=<srcversion>]
    LAPS <config> laps_before_board=<max over rows> rows=<id,id,...>

A row that is SKIP, NOT RUN, or earned on another build than --build is
listed too (runs_needed=1): nothing but a run on this build makes it a PASS,
and a SKIP stays one until whatever it skipped for is supplied.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import criteria  # noqa: E402


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    build = ""
    if "--build" in sys.argv:
        build = sys.argv[sys.argv.index("--build") + 1]
        args = [a for a in args if a != build]
    if len(args) != 2:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    config = "%s/%s" % (args[0], args[1])
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "criteria.json")
    with open(path) as fh:
        rows = json.load(fh)["criteria"]
    owed = 0
    owing = []
    for entry in rows:
        if not criteria.applies(entry, config):
            continue
        cell = criteria.cell_of(entry, config)
        rid = str(entry.get("id", ""))
        if not cell:
            print("ROW %s status=UNMEASURED newest_fail=- runs_needed=1 laps_before_board=0" % rid)
            continue
        status = str(cell.get("status", "")).upper().strip()
        runs = ([cell] + list(cell.get("history") or []))[:criteria.FLAKE_WINDOW]
        newest = -1
        if rid not in criteria.NEVER_FLAKE:
            for k, r in enumerate(runs):
                if (str(r.get("status", "")).upper().strip() == "FAIL"
                        and not criteria.RIG_NOISE.search(str(r.get("reason", "")))
                        and not r.get("detector_defect")):
                    newest = k
                    break
        stale = bool(build) and str(cell.get("build", "")) != build
        if newest < 0 and status == "PASS" and not stale:
            continue
        if newest >= 0:
            need = criteria.FLAKE_WINDOW - newest
            laps = max(need - 1, 0)
        else:
            need, laps = 1, 0
        if laps > 0:
            owing.append(rid)
        owed = max(owed, laps)
        print("ROW %s status=%s newest_fail=%s runs_needed=%d laps_before_board=%d build=%s%s"
              % (rid, status or "-", newest if newest >= 0 else "-", need, laps,
                 cell.get("build", "-"), " (not this build)" if stale else ""))
    print("LAPS %s laps_before_board=%d rows=%s" % (config, owed, ",".join(owing) or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
