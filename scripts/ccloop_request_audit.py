#!/usr/bin/env python3
"""Measure loop cost in REQUESTS, the currency the Fable quota actually charges.

Why this exists (2026-08-15):

  docs/cost-audit.md measured everything in tokens -- raw and weighted -- and
  §5 was left open on which of the two the subscription quota counts. The
  answer is NEITHER. Four consecutive credit exhaustions land at a nearly
  constant number of *Fable requests* while the token totals for the same
  weeks vary by 2.5x:

      week      exhausted        fable reqs   fable raw tok   fable weighted
      07-24     07-26 21:57Z          4,244        2,709.4M          383.1M
      07-31     08-03 12:50Z          4,635        2,962.0M          384.3M
      08-07     08-11 03:29Z          4,338        1,049.4M          198.1M
      08-14     08-15 20:37Z          4,509        1,174.8M          220.3M
      CV                                3.9%           49.9%           34.7%

  The 500k -> 145k cutoff change cut tokens per week by 2.5x and the week
  still ran out of credits at the same request count. Token efficiency does
  not buy loop time.

  The pool is also FABLE-ONLY, not account-wide: opus requests in the same
  weeks range 2,191..9,372 with no effect on when Fable dies.

So the metric that matters is requests per unit of work. This script reports
requests per session, per productive action, and per closure, bucketed by
observed peak context -- the same buckets docs/cost-audit.md §3.2.1 used for
weighted tokens, so the two are directly comparable.

A "request" is a distinct requestId in the transcript. One assistant response
may be split across several transcript records (text block + tool_use block),
so counting records overstates requests by ~2.3x; both are reported.

Usage:
  scripts/ccloop_request_audit.py [--projects-dir DIR] [--project -src-mxfs]
                                  [--from ISO] [--to ISO] [--min-turns N]
"""
import argparse
import glob
import json
import re
from collections import defaultdict
from datetime import datetime, timezone

PRODUCTIVE_TOOLS = {"Edit", "Write", "NotebookEdit", "MultiEdit"}
PRODUCTIVE_BASH = re.compile(
    r"\b(make|gcc|insmod|rmmod|modprobe|virsh|ssh|scp|rsync|mount|umount|"
    r"mkfs_mxfs|chk_mxfs|dmsetup|tests/|scripts/|bench/|tools/)\b")

BUCKETS = [(0, 100_000), (100_000, 175_000), (175_000, 300_000),
           (300_000, 420_000), (420_000, 10**12)]


def bucket(peak):
    for lo, hi in BUCKETS:
        if lo <= peak < hi:
            return f"{lo//1000}-{hi//1000}k" if hi < 10**12 else ">420k"
    return "?"


def family(model):
    for f in ("fable", "opus", "sonnet", "haiku"):
        if f in model:
            return f
    return model


def scan(path):
    """-> dict of per-session stats, or None if it has no billable turns."""
    reqs, records, prod, tools = set(), 0, 0, 0
    peak = 0
    models = defaultdict(int)
    first = last = None
    with open(path, errors="replace") as fh:
        for line in fh:
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
            ts = rec.get("timestamp")
            if ts:
                t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                first = t if first is None else min(first, t)
                last = t if last is None else max(last, t)
            models[family(model)] += 1
            records += 1
            reqs.add(rec.get("requestId") or msg.get("id") or f"{records}")
            u = msg.get("usage") or {}
            ctx = ((u.get("input_tokens") or 0)
                   + (u.get("cache_creation_input_tokens") or 0)
                   + (u.get("cache_read_input_tokens") or 0))
            peak = max(peak, ctx)
            content = msg.get("content") or []
            if not isinstance(content, list):
                continue
            for block in content:
                if not (isinstance(block, dict)
                        and block.get("type") == "tool_use"):
                    continue
                tools += 1
                name = block.get("name", "")
                if name in PRODUCTIVE_TOOLS:
                    prod += 1
                elif name == "Bash" and PRODUCTIVE_BASH.search(
                        str((block.get("input") or {}).get("command", ""))):
                    prod += 1
    if not records:
        return None
    return dict(requests=len(reqs), records=records, productive=prod,
                tools=tools, peak=peak, first=first, last=last,
                model=max(models, key=models.get))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects-dir", default="/home/steve/.claude/projects")
    ap.add_argument("--project", default="-src-mxfs")
    ap.add_argument("--from", dest="lo")
    ap.add_argument("--to", dest="hi")
    ap.add_argument("--min-turns", type=int, default=20)
    ap.add_argument("--exclude", action="append", default=[])
    args = ap.parse_args()

    def parse(s):
        if not s:
            return None
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)

    lo, hi = parse(args.lo), parse(args.hi)

    sessions = []
    for path in glob.glob(f"{args.projects_dir}/{args.project}/*.jsonl"):
        if any(e in path for e in args.exclude):
            continue
        s = scan(path)
        if not s or s["records"] < args.min_turns:
            continue
        if lo and (s["last"] is None or s["last"] < lo):
            continue
        if hi and (s["first"] is None or s["first"] > hi):
            continue
        sessions.append(s)

    if not sessions:
        print("no sessions matched")
        return

    agg = defaultdict(lambda: defaultdict(lambda: [0, 0, 0, 0, 0]))
    for s in sessions:
        a = agg[s["model"]][bucket(s["peak"])]
        a[0] += 1
        a[1] += s["requests"]
        a[2] += s["records"]
        a[3] += s["productive"]
        a[4] += s["tools"]

    print(f"{len(sessions)} sessions, project {args.project}"
          + (f", {args.lo}..{args.hi}" if lo or hi else ""))
    print("\nrequests per productive action, by observed peak context")
    print(f"{'model':8s} {'bucket':>10s} {'sess':>5s} {'reqs':>8s} "
          f"{'recs/req':>8s} {'prod':>6s} {'req/prod':>9s} {'req/sess':>9s}")
    for model in sorted(agg):
        base = None
        for lo_, hi_ in BUCKETS:
            b = f"{lo_//1000}-{hi_//1000}k" if hi_ < 10**12 else ">420k"
            a = agg[model].get(b)
            if not a:
                continue
            rpp = a[1] / a[3] if a[3] else float("nan")
            if base is None and a[3]:
                base = rpp
            print(f"{model:8s} {b:>10s} {a[0]:5d} {a[1]:8d} "
                  f"{a[2]/a[1]:8.2f} {a[3]:6d} {rpp:9.2f} {a[1]/a[0]:9.1f}"
                  + (f"   {rpp/base:.2f}x" if base else ""))
    tot_r = sum(s["requests"] for s in sessions)
    tot_p = sum(s["productive"] for s in sessions)
    print(f"\ntotal: {tot_r:,} requests, {tot_p:,} productive actions, "
          f"{tot_r/tot_p:.2f} req/prod")


if __name__ == "__main__":
    main()
