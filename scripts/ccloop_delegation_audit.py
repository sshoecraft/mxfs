#!/usr/bin/env python3
"""Delegation half of the MXFS session-cost audit (docs/cost-audit.md, docs/delegation.md).

The Fable pool is metered in REQUESTS (cost-audit banner).  the delegation rule exists to
move mechanical work (fleet polls, harness runs, builds, tree sweeps, log
parsing) to sonnet/haiku subagents so it does not spend Fable requests.  This
script answers, per session and per run:

  * where each Fable request went, by kind of work (Read/Edit vs the
    mechanical Bash categories),
  * how many requests were spent inside CHAINS of consecutive mechanical
    requests -- the only shape where delegation saves anything: an Agent call
    costs one request, so a chain of N mechanical requests collapsed into one
    Agent call saves N-1,
  * how many Agent calls the session actually made, and what the subagents
    billed (model, requestIds) from <session>/subagents/agent-*.jsonl.

Usage:
  scripts/ccloop_delegation_audit.py --run <ccloop-run-id> --from-session N [--to-session M]
  scripts/ccloop_delegation_audit.py --since 2026-08-21T20:00 [--until ...]
  scripts/ccloop_delegation_audit.py --files <uuid-prefix> [<uuid-prefix> ...]
  add --model claude-opus-5 to audit an Opus era (default claude-fable-5)
  add --per-session for one row per session

Mechanical categories (delegable):
  fleet-ssh       tools/mxfs_sshpass.sh / virsh sweeps
  harness-run     run.sh, showstat, tests/*.sh, bench/*
  build-deploy    make, scp mxfs.ko, insmod/rmmod/modinfo
  text/listing    grep/sed -n/cat/head/tail/wc/ls/find/awk/diff as the command
  transcript      python3 parsing of ~/.claude/projects/*.jsonl
  ledger          defects.sh / OPEN_DEFECTS.json queries
  dmesg-local     dmesg/journalctl on the host
Premium (stays in the parent): Read, Edit, Write, ccmemory, ask_gpt, design.
"""
import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

RUNS = "/src/mxfs/.ccloop/runs"
PROJECT_DIR = "/home/steve/.claude/projects/-src-mxfs"

MECH = ("fleet-ssh", "harness-run", "build-deploy", "text/listing",
        "transcript", "ledger", "dmesg-local")

R_FLEET = re.compile(r"mxfs_sshpass|\bvirsh\b")
R_HARNESS = re.compile(r"\brun\.sh\b|showstat|run_tests|\btests/[A-Za-z0-9_]+\.sh|\bbench/")
R_BUILD = re.compile(r"\bmake\b|scp .*mxfs\.ko|\binsmod\b|\brmmod\b|\bmodinfo\b")
R_LEDGER = re.compile(r"defects\.sh|OPEN_DEFECTS")
R_DMESG = re.compile(r"\bdmesg\b|\bjournalctl\b")
R_LIST = re.compile(r"(^|[;&|]\s*|\bcd [^;]*;\s*)(grep|rg|sed -n|cat|head|tail|wc|ls|find|awk|diff|stat|file)\b")


def classify(name, inp):
    if name != "Bash":
        return name
    c = inp.get("command", "") or ""
    if R_FLEET.search(c):
        return "fleet-ssh"
    if R_HARNESS.search(c):
        return "harness-run"
    if R_BUILD.search(c):
        return "build-deploy"
    if "python3" in c and ".jsonl" in c:
        return "transcript"
    if R_LEDGER.search(c):
        return "ledger"
    if R_DMESG.search(c):
        return "dmesg-local"
    if R_LIST.search(c):
        return "text/listing"
    return "Bash:other"


def session_files_for_run(run_id, frm, to):
    log = os.path.join(RUNS, run_id, "sessions.log")
    ids = [l.strip() for l in open(log) if l.strip()]
    sel = ids[frm - 1: (to if to else len(ids))]
    out = []
    for sid in sel:
        p = os.path.join(PROJECT_DIR, sid + ".jsonl")
        if os.path.isfile(p):
            out.append(p)
    return out


def audit_session(path, model):
    """Return a dict of per-session numbers for requests made by `model`."""
    req_cat = {}          # requestId -> set(categories)
    req_order = []        # requestIds in first-seen order
    agent_calls = 0
    tool_calls = Counter()
    first_ts = last_ts = None
    for line in open(path):
        if '"assistant"' not in line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if d.get("type") != "assistant" or d.get("isSidechain"):
            continue
        m = d.get("message", {})
        # Prefix match, not equality: the pool model gets renamed under us
        # (claude-fable-5 -> claude-fable-5-1 on 2026-09-04) and an exact
        # match then reports "no sessions", which reads as "delegation is
        # unmeasurable" rather than "the filter missed".
        if not (m.get("model") or "").startswith(model):
            continue
        rid = d.get("requestId")
        if not rid:
            continue
        ts = d.get("timestamp")
        first_ts = first_ts or ts
        last_ts = ts or last_ts
        if rid not in req_cat:
            req_cat[rid] = set()
            req_order.append(rid)
        for b in m.get("content") or []:
            if b.get("type") == "tool_use":
                k = classify(b["name"], b.get("input", {}))
                req_cat[rid].add(k)
                tool_calls[k] += 1
                if b["name"] == "Agent":
                    agent_calls += 1
    # per-request dominant category: mechanical if ALL its tool calls are mechanical
    cats = Counter()
    mech_flags = []
    for rid in req_order:
        ks = req_cat[rid]
        if not ks:
            cats["no-tool (text/thinking only)"] += 1
            mech_flags.append(False)
            continue
        for k in ks:
            cats[k] += 1 / len(ks)
        mech_flags.append(all(k in MECH for k in ks))
    # chains of consecutive mechanical requests
    chains = []
    run = 0
    for f in mech_flags:
        if f:
            run += 1
        else:
            if run:
                chains.append(run)
            run = 0
    if run:
        chains.append(run)
    chain_ge3 = [c for c in chains if c >= 3]
    saveable = sum(c - 1 for c in chain_ge3)
    # subagent billing
    sub = Counter()
    sub_req = Counter()
    sdir = path[:-len(".jsonl")] + "/subagents"
    for sp in glob.glob(os.path.join(sdir, "agent-*.jsonl")):
        rids = set()
        mdl = None
        for line in open(sp):
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("type") == "assistant":
                mdl = d.get("message", {}).get("model") or mdl
                if d.get("requestId"):
                    rids.add(d["requestId"])
        if mdl:
            sub[mdl] += 1
            sub_req[mdl] += len(rids)
    return {
        "file": os.path.basename(path)[:8],
        "first": first_ts, "last": last_ts,
        "requests": len(req_order),
        "mech_requests": sum(mech_flags),
        "cats": cats, "tool_calls": tool_calls,
        "agent_calls": agent_calls,
        "chains": chains, "chain_ge3": chain_ge3, "saveable": saveable,
        "sub_agents": sub, "sub_requests": sub_req,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run")
    ap.add_argument("--from-session", type=int, default=1)
    ap.add_argument("--to-session", type=int)
    ap.add_argument("--since")
    ap.add_argument("--until")
    ap.add_argument("--files", nargs="*")
    ap.add_argument("--model", default="claude-fable",
                    help="model-id PREFIX to audit (default claude-fable, "
                         "which covers fable-5 and fable-5-1)")
    ap.add_argument("--per-session", action="store_true")
    a = ap.parse_args()

    if a.run:
        files = session_files_for_run(a.run, a.from_session, a.to_session)
    elif a.files:
        files = []
        for pre in a.files:
            files += glob.glob(os.path.join(PROJECT_DIR, pre + "*.jsonl"))
    elif a.since:
        import datetime
        lo = datetime.datetime.fromisoformat(a.since).timestamp()
        hi = datetime.datetime.fromisoformat(a.until).timestamp() if a.until else float("inf")
        files = [p for p in glob.glob(os.path.join(PROJECT_DIR, "*.jsonl"))
                 if lo <= os.path.getmtime(p) and os.path.getmtime(p) - 86400 * 3 <= hi]
    else:
        ap.error("give --run, --since or --files")

    rows = [audit_session(p, a.model) for p in files]
    rows = [r for r in rows if r["requests"]]
    if not rows:
        print("no sessions with requests for model", a.model)
        return 1
    tot_req = sum(r["requests"] for r in rows)
    tot_mech = sum(r["mech_requests"] for r in rows)
    tot_save = sum(r["saveable"] for r in rows)
    tot_agent = sum(r["agent_calls"] for r in rows)
    cats = Counter()
    for r in rows:
        cats.update(r["cats"])
    sub = Counter()
    subr = Counter()
    for r in rows:
        sub.update(r["sub_agents"])
        subr.update(r["sub_requests"])

    print(f"model={a.model} sessions={len(rows)} requests={tot_req}")
    print(f"  mechanical requests (all tool calls delegable): {tot_mech} ({100*tot_mech/tot_req:.0f}%)")
    print(f"  chains of >=3 consecutive mechanical requests: {sum(len(r['chain_ge3']) for r in rows)}"
          f"  -> requests SAVEABLE by one Agent call per chain: {tot_save} ({100*tot_save/tot_req:.0f}% of all requests)")
    print(f"  Agent calls made: {tot_agent}   subagent runs by model: {dict(sub)}   subagent requests: {dict(subr)}")
    print("  requests by category (fractional when a request mixes tools):")
    for k, v in cats.most_common():
        tag = "  [delegable]" if k in MECH else ""
        print(f"    {k:32s} {v:7.1f}  ({100*v/tot_req:4.1f}%){tag}")
    if a.per_session:
        print("\n  per session: file  first..last  requests  mech  chains>=3  saveable  Agent  subagent-reqs")
        for r in rows:
            print(f"    {r['file']}  {(r['first'] or '')[5:16]}..{(r['last'] or '')[11:16]}  {r['requests']:5d} {r['mech_requests']:5d}"
                  f"  {len(r['chain_ge3']):5d}  {r['saveable']:5d}  {r['agent_calls']:4d}  {dict(r['sub_requests'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
