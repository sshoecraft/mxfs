#!/usr/bin/env python3
"""Audit real token consumption per Claude Code session from transcript JSONL.

Reads ~/.claude/projects/<slug>/*.jsonl, sums the usage block on every
assistant message, and reports per-session and aggregate numbers.

The point of interest: how much of each session's billed input is the
*startup prefix* (system prompt + CLAUDE.md + tool schemas + hooks +
memory_list + ccloop resume prompt) that gets re-paid on every restart,
versus tokens spent on actual work.

Usage:
    python3 scripts/ccloop_token_audit.py [--project-dir DIR] [--since-hours N]
"""

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

# Anthropic relative billing weights (cache reads are cheap, writes cost a
# premium over base input). Used only to produce a weighted "effective input
# tokens" figure comparable across sessions.
W_INPUT = 1.0
W_CACHE_WRITE = 1.25
W_CACHE_READ = 0.10
W_OUTPUT = 5.0


def parse_ts(rec):
    ts = rec.get("timestamp")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def audit_file(path):
    """Return per-session stats dict, or None if the file has no usage data."""
    stats = {
        "path": path,
        "session_id": os.path.basename(path)[:-6],
        "input": 0,
        "cache_write": 0,
        "cache_read": 0,
        "output": 0,
        "assistant_turns": 0,
        "first_ts": None,
        "last_ts": None,
        # context size of the very first assistant turn == startup prefix
        "first_turn_context": None,
        "max_context": 0,
    }

    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = parse_ts(rec)
            if ts:
                if stats["first_ts"] is None or ts < stats["first_ts"]:
                    stats["first_ts"] = ts
                if stats["last_ts"] is None or ts > stats["last_ts"]:
                    stats["last_ts"] = ts

            msg = rec.get("message")
            if not isinstance(msg, dict):
                continue
            usage = msg.get("usage")
            if not isinstance(usage, dict):
                continue

            inp = usage.get("input_tokens", 0) or 0
            cw = usage.get("cache_creation_input_tokens", 0) or 0
            cr = usage.get("cache_read_input_tokens", 0) or 0
            out = usage.get("output_tokens", 0) or 0

            stats["input"] += inp
            stats["cache_write"] += cw
            stats["cache_read"] += cr
            stats["output"] += out
            stats["assistant_turns"] += 1

            ctx = inp + cw + cr
            if stats["first_turn_context"] is None and ctx > 0:
                stats["first_turn_context"] = ctx
            if ctx > stats["max_context"]:
                stats["max_context"] = ctx

    if stats["assistant_turns"] == 0:
        return None

    stats["weighted"] = (
        stats["input"] * W_INPUT
        + stats["cache_write"] * W_CACHE_WRITE
        + stats["cache_read"] * W_CACHE_READ
        + stats["output"] * W_OUTPUT
    )
    return stats


def fmt(n):
    n = float(n)
    if n >= 1e9:
        return f"{n/1e9:.2f}B"
    if n >= 1e6:
        return f"{n/1e6:.1f}M"
    if n >= 1e3:
        return f"{n/1e3:.1f}k"
    return f"{n:.0f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--project-dir",
        default=os.path.expanduser("~/.claude/projects/-src-mxfs"),
        help="Claude Code project transcript directory",
    )
    ap.add_argument(
        "--since-hours",
        type=float,
        default=None,
        help="only include sessions whose last activity is within N hours",
    )
    args = ap.parse_args()

    paths = sorted(glob.glob(os.path.join(args.project_dir, "*.jsonl")))
    if not paths:
        print(f"no transcripts under {args.project_dir}", file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc)
    sessions = []
    for p in paths:
        s = audit_file(p)
        if s is None:
            continue
        if args.since_hours is not None and s["last_ts"] is not None:
            age_h = (now - s["last_ts"]).total_seconds() / 3600.0
            if age_h > args.since_hours:
                continue
        sessions.append(s)

    if not sessions:
        print("no sessions matched", file=sys.stderr)
        return 1

    sessions.sort(key=lambda s: s["first_ts"] or now)

    hdr = (
        f"{'started':16} {'turns':>6} {'startup':>8} {'peak':>8} "
        f"{'c-read':>9} {'c-write':>9} {'input':>8} {'output':>8} {'weighted':>10}"
    )
    print(hdr)
    print("-" * len(hdr))

    tot = defaultdict(float)
    for s in sessions:
        started = s["first_ts"].astimezone().strftime("%m-%d %H:%M") if s["first_ts"] else "?"
        print(
            f"{started:16} {s['assistant_turns']:>6} "
            f"{fmt(s['first_turn_context'] or 0):>8} {fmt(s['max_context']):>8} "
            f"{fmt(s['cache_read']):>9} {fmt(s['cache_write']):>9} "
            f"{fmt(s['input']):>8} {fmt(s['output']):>8} {fmt(s['weighted']):>10}"
        )
        for k in ("cache_read", "cache_write", "input", "output", "weighted", "assistant_turns"):
            tot[k] += s[k]

    print("-" * len(hdr))
    print(
        f"{'TOTAL ('+str(len(sessions))+' sess)':16} {int(tot['assistant_turns']):>6} "
        f"{'':>8} {'':>8} "
        f"{fmt(tot['cache_read']):>9} {fmt(tot['cache_write']):>9} "
        f"{fmt(tot['input']):>8} {fmt(tot['output']):>8} {fmt(tot['weighted']):>10}"
    )

    # Startup-overhead accounting.
    startups = [s["first_turn_context"] or 0 for s in sessions]
    avg_startup = sum(startups) / len(startups)
    # Every session re-pays its startup prefix as cache-write at least once,
    # and re-reads it on every subsequent turn.
    restart_write = sum(startups) * W_CACHE_WRITE
    prefix_rereads = sum(
        (s["first_turn_context"] or 0) * max(0, s["assistant_turns"] - 1) * W_CACHE_READ
        for s in sessions
    )

    print()
    print("=== startup-prefix accounting ===")
    print(f"sessions                : {len(sessions)}")
    print(f"avg startup prefix      : {fmt(avg_startup)} tokens")
    print(f"avg peak context        : {fmt(sum(s['max_context'] for s in sessions)/len(sessions))} tokens")
    print(f"avg turns per session   : {tot['assistant_turns']/len(sessions):.0f}")
    print(f"prefix cache-writes     : {fmt(restart_write)} weighted  "
          f"({100*restart_write/tot['weighted']:.1f}% of total)")
    print(f"prefix re-reads         : {fmt(prefix_rereads)} weighted  "
          f"({100*prefix_rereads/tot['weighted']:.1f}% of total)")
    print(f"total prefix cost       : {fmt(restart_write+prefix_rereads)} weighted  "
          f"({100*(restart_write+prefix_rereads)/tot['weighted']:.1f}% of total)")

    span_h = None
    first = min((s["first_ts"] for s in sessions if s["first_ts"]), default=None)
    last = max((s["last_ts"] for s in sessions if s["last_ts"]), default=None)
    if first and last:
        span_h = (last - first).total_seconds() / 3600.0
        print()
        print(f"wall span               : {span_h:.1f}h")
        print(f"weighted burn rate      : {fmt(tot['weighted']/span_h)}/hour")

    return 0


if __name__ == "__main__":
    sys.exit(main())
