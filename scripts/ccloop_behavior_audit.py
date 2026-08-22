#!/usr/bin/env python3
"""Behavioural half of the MXFS session-cost audit (docs/cost-audit.md).

`ccloop_token_audit.py` answers "how many tokens". This answers "did the
2026-08-07 behavioural interventions actually change what sessions do":

  #4 handoff tier (RULE 8) -- how often is .ccloop/handoff.md FRESH at the
     start of a session, i.e. did the previous session actually maintain it
  #5 RULE 7 (Read tool)    -- Read-tool calls vs Bash file-reads per session
     (baseline 2026-08-07: 2.5 Read vs 19.5 Bash reads/session = 11% Read)
  orientation ramp         -- tool calls before the first productive action
     (baseline: median 16), and the most re-read files across the run

Usage:
  scripts/ccloop_behavior_audit.py --run <ccloop-run-id> --from-session 174
  scripts/ccloop_behavior_audit.py --run <run-id> --from-session 1 --to-session 173

Session numbering follows session-N.prompt / the Nth line of sessions.log.
"""
import argparse
import json
import os
import re
import statistics
import sys
from collections import Counter

RUNS = "/src/mxfs/.ccloop/runs"
PROJECT_DIR = "/home/steve/.claude/projects/-src-mxfs"

# Bash invocations that are really "read a source file to understand it".
BASH_READ = re.compile(r"\b(sed\s+-n|cat|head|tail|less|more)\b")
# A productive action ends the orientation ramp: mutate code, or run the rig.
PRODUCTIVE_TOOLS = {"Edit", "Write", "NotebookEdit", "MultiEdit"}
PRODUCTIVE_BASH = re.compile(
    r"\b(make|gcc|insmod|rmmod|modprobe|virsh|ssh|scp|rsync|mount|umount|"
    r"mkfs_mxfs|chk_mxfs|dmsetup|tests/|scripts/|bench/|tools/)\b"
)


def session_ids(run, lo, hi):
    """Map session number -> transcript uuid via sessions.log line order."""
    with open(f"{RUNS}/{run}/sessions.log") as fh:
        ids = [l.strip() for l in fh if l.strip()]
    return [(n, ids[n - 1]) for n in range(lo, min(hi, len(ids)) + 1)]


def handoff_freshness(run, pairs):
    """Intervention #4: did ccloop stamp the handoff FRESH or STALE?"""
    fresh = stale = missing = 0
    sizes = []
    for n, _ in pairs:
        path = f"{RUNS}/{run}/session-{n}.prompt"
        if not os.path.exists(path):
            missing += 1
            continue
        text = open(path, errors="replace").read()
        sizes.append(len(text))
        if "## Handoff from the previous session" not in text:
            missing += 1
        elif "**STALE" in text:
            stale += 1
        else:
            fresh += 1
    return fresh, stale, missing, sizes


def walk_tools(path):
    """Yield (tool_name, tool_input) for every assistant tool call, in order."""
    with open(path, errors="replace") as fh:
        for line in fh:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("type") != "assistant":
                continue
            content = (d.get("message") or {}).get("content") or []
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    yield block.get("name", ""), block.get("input") or {}


def classify(name, inp):
    """-> ('read'|'productive'|'other', is_bash)"""
    if name == "Read":
        return "read", False
    if name in PRODUCTIVE_TOOLS:
        return "productive", False
    if name == "Bash":
        cmd = str(inp.get("command", ""))
        if PRODUCTIVE_BASH.search(cmd):
            return "productive", True
        if BASH_READ.search(cmd):
            return "read", True
        return "other", True
    return "other", False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--from-session", type=int, default=1)
    ap.add_argument("--to-session", type=int, default=10**6)
    ap.add_argument("--project-dir", default=PROJECT_DIR)
    args = ap.parse_args()

    pairs = session_ids(args.run, args.from_session, args.to_session)
    if not pairs:
        sys.exit("no sessions in range")

    fresh, stale, missing, sizes = handoff_freshness(args.run, pairs)

    read_tool, bash_read, ramps, seen = [], [], [], 0
    files = Counter()
    mem_calls = Counter()
    for n, sid in pairs:
        path = f"{args.project_dir}/{sid}.jsonl"
        if not os.path.exists(path):
            continue
        seen += 1
        r = b = 0
        ramp = None
        for i, (name, inp) in enumerate(walk_tools(path)):
            if name.startswith("mcp__ccmemory__"):
                mem_calls[name.rsplit("__", 1)[-1]] += 1
            kind, is_bash = classify(name, inp)
            if kind == "read":
                if is_bash:
                    b += 1
                else:
                    r += 1
                    fp = inp.get("file_path")
                    if fp:
                        files[fp] += 1
            if kind == "productive" and ramp is None:
                ramp = i
        read_tool.append(r)
        bash_read.append(b)
        if ramp is not None:
            ramps.append(ramp)

    n = len(pairs)
    print(f"run {args.run[:8]}  sessions {args.from_session}-{pairs[-1][0]} "
          f"({n} prompts, {seen} transcripts found)\n")

    print("=== #4 handoff tier (RULE 8) ===")
    tot = fresh + stale + missing
    print(f"  FRESH   : {fresh:4d}  ({100*fresh/tot:.0f}%)")
    print(f"  STALE   : {stale:4d}  ({100*stale/tot:.0f}%)")
    print(f"  absent  : {missing:4d}")
    if sizes:
        print(f"  prompt bytes: mean {statistics.mean(sizes):.0f}  "
              f"median {statistics.median(sizes):.0f}  "
              f"min {min(sizes)}  max {max(sizes)}")

    print("\n=== #5 RULE 7 (Read tool vs Bash file-reads) ===")
    tr, tb = sum(read_tool), sum(bash_read)
    if tr + tb:
        print(f"  Read tool    : {tr:6d}  ({tr/max(seen,1):.1f}/session)  "
              f"{100*tr/(tr+tb):.0f}% of file reads")
        print(f"  Bash reads   : {tb:6d}  ({tb/max(seen,1):.1f}/session)")

    print("\n=== orientation ramp ===")
    if ramps:
        print(f"  tool calls before first productive action: "
              f"median {statistics.median(ramps):.0f}  "
              f"mean {statistics.mean(ramps):.1f}  "
              f"range {min(ramps)}-{max(ramps)}  (n={len(ramps)})")

    print("\n=== most Read-tool-read files ===")
    for fp, c in files.most_common(10):
        print(f"  {c:4d}  {fp}")

    print("\n=== ccmemory calls ===")
    for k, c in mem_calls.most_common():
        print(f"  {k:16s} {c:5d}  ({c/max(seen,1):.2f}/session)")


if __name__ == "__main__":
    main()
