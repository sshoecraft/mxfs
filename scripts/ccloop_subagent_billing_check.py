#!/usr/bin/env python3
"""Does subagent work bill to the SUBAGENT's model pool, not the parent's?

Why this matters (2026-08-15): the weekly quota is counted in *Fable requests*
-- ~4,430/week, see docs/cost-audit.md. In the week of 08-14 the loop spent
53% of those requests on file reads and greps and 16% on anything that
mutated code. If a Fable session can push mechanical work (fleet polls, log
sweeps, builds) onto a subagent pinned to `model: sonnet` or `model: opus`,
and those requests are served by the subagent's model, then the Fable ration
buys reasoning instead of plumbing.

That "if" was unverified: across 803 transcripts, ZERO subagent turns had ever
run in this project, so there was no data either way. This script reads the
answer straight out of the transcripts.

How it works: Claude Code marks subagent turns with `isSidechain: true` and
stamps every assistant record with the model that served it. So a session
whose main turns are opus and whose sidechain turns are sonnet is direct
evidence that the override reaches the API, and the sonnet turns are not
charged to the parent's pool.

Usage:
  scripts/ccloop_subagent_billing_check.py [--projects-dir DIR] [--session UUID]
"""
import argparse
import glob
import json
from collections import Counter, defaultdict


def scan(path):
    main, side = Counter(), Counter()
    main_reqs, side_reqs = set(), set()
    for line in open(path, errors="replace"):
        if '"assistant"' not in line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("type") != "assistant":
            continue
        msg = rec.get("message") or {}
        model = msg.get("model", "")
        if not model.startswith("claude"):
            continue
        fam = model.replace("claude-", "").split("[")[0]
        rid = rec.get("requestId") or msg.get("id")
        if rec.get("isSidechain"):
            side[fam] += 1
            side_reqs.add(rid)
        else:
            main[fam] += 1
            main_reqs.add(rid)
    return main, side, main_reqs, side_reqs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects-dir", default="/home/steve/.claude/projects")
    ap.add_argument("--project", default="-src-mxfs")
    ap.add_argument("--session", help="restrict to one transcript uuid prefix")
    args = ap.parse_args()

    found = 0
    totals = defaultdict(lambda: [0, 0])
    for path in sorted(glob.glob(f"{args.projects_dir}/{args.project}/*.jsonl")):
        if args.session and args.session not in path:
            continue
        main, side, mreq, sreq = scan(path)
        if not side:
            continue
        found += 1
        uuid = path.split("/")[-1][:8]
        pm = max(main, key=main.get) if main else "?"
        print(f"session {uuid}")
        print(f"  parent   : {pm}  ({len(mreq)} requests, {sum(main.values())} records)")
        for fam, n in side.most_common():
            print(f"  subagent : {fam}  ({n} records)")
            totals[fam][0] += n
        print(f"  sidechain requests: {len(sreq)}")
        verdict = ("SPLIT — subagent billed to a different model"
                   if any(f != pm for f in side)
                   else "SAME model as parent (no billing split shown)")
        print(f"  => {verdict}\n")

    if not found:
        print("No subagent (isSidechain) turns found.\n"
              "Either none have run yet, or the agent completed after this "
              "transcript was last flushed -- re-run in a moment.")
        return
    print("totals by subagent model:",
          {k: v[0] for k, v in totals.items()})


if __name__ == "__main__":
    main()
