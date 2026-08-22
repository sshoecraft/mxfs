#!/usr/bin/env python3
"""Settle docs/cost-audit.md §5: does the subscription quota count RAW or
WEIGHTED tokens?

`ccloop_token_audit.py` reports both metrics for one project, but cannot say
which one the quota actually charges -- and the two disagree about where the
money goes (raw: 98.8% is cache read, output is noise; weighted: output is a
third of cost). Every "is this lever worth pulling" question depends on which.

The experiment this script runs:

  A credit-exhaustion event ("You're out of usage credits") is a direct
  observation that the quota hit 100%. Total each quota period in both
  metrics; across independent periods the cap is the same number, so the
  metric that reproduces a CONSISTENT total at exhaustion is the one being
  counted and the metric that scatters is not.

Two facts about the pool, established 2026-08-11 and baked in below:

  * It is ACCOUNT-WIDE across models and projects, not per-model. Exhaustion
    blocks the premium model while cheaper ones keep serving, so "the
    premium model went quiet" is a symptom, not the pool boundary. Every
    billable claude-* turn in EVERY project counts; local/ollama models do
    not.
  * It resets WEEKLY, Thursday ~04:00Z (observed 07-24 04:00Z, 07-31 04:16Z,
    08-07 04:03Z -- 7d apart to within 16 min). Do NOT infer the boundary
    from a gap in activity: a silence usually means nobody was working, and
    that heuristic put boundaries 38-127h apart and made both metrics look
    equally inconsistent.

Usage:
  scripts/ccloop_quota_probe.py [--projects-dir DIR] [--weeks N]
"""
import argparse
import glob
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# Same weights as ccloop_token_audit.py -- the hypothesis under test.
W_INPUT, W_CACHE_WRITE, W_CACHE_READ, W_OUTPUT = 1.0, 1.25, 0.10, 5.0

EXHAUSTED = "out of usage credits"

# Weekly reset boundary. Anchor is an observed reset; periods step 7d from it.
RESET_ANCHOR = datetime(2026, 7, 24, 4, 0, tzinfo=timezone.utc)


def parse_ts(rec):
    ts = rec.get("timestamp")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def collect(projects_dir, exclude):
    """-> (turns, exhaustions). turns = [(ts, in, cw, cr, out, project, model)]."""
    turns, exhaustions = [], []
    for path in glob.glob(f"{projects_dir}/*/*.jsonl"):
        if any(e in path for e in exclude):
            continue
        project = path.split("/")[-2]
        with open(path, errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("type") != "assistant":
                    continue
                ts = parse_ts(rec)
                if ts is None:
                    continue
                msg = rec.get("message") or {}
                if EXHAUSTED in json.dumps(msg.get("content", "")):
                    exhaustions.append((ts, project))
                    continue
                model = msg.get("model", "?")
                # Local/self-hosted models bill nothing against the quota.
                if not model.startswith("claude"):
                    continue
                u = msg.get("usage") or {}
                turns.append((
                    ts,
                    u.get("input_tokens", 0) or 0,
                    u.get("cache_creation_input_tokens", 0) or 0,
                    u.get("cache_read_input_tokens", 0) or 0,
                    u.get("output_tokens", 0) or 0,
                    project,
                    model,
                ))
    turns.sort(key=lambda r: r[0])
    exhaustions.sort()
    return turns, exhaustions


def weeks(turns, n_weeks):
    """Weekly [lo, hi) periods from RESET_ANCHOR that contain any activity."""
    if not turns:
        return []
    last = turns[-1][0]
    out = []
    lo = RESET_ANCHOR
    while lo < last:
        out.append((lo, lo + timedelta(days=7)))
        lo += timedelta(days=7)
    return out[-n_weeks:] if n_weeks else out


def totals(turns, lo, hi):
    inp = cw = cr = out = 0
    by_project = defaultdict(float)
    by_model = defaultdict(float)
    n = 0
    for ts, i_, cw_, cr_, o_, proj, model in turns:
        if not (lo <= ts < hi):
            continue
        inp += i_
        cw += cw_
        cr += cr_
        out += o_
        n += 1
        w = (i_ * W_INPUT + cw_ * W_CACHE_WRITE
             + cr_ * W_CACHE_READ + o_ * W_OUTPUT)
        by_project[proj] += w
        by_model[model] += w
    raw = inp + cw + cr + out
    weighted = (inp * W_INPUT + cw * W_CACHE_WRITE
                + cr * W_CACHE_READ + out * W_OUTPUT)
    return dict(turns=n, input=inp, cache_write=cw, cache_read=cr,
                output=out, raw=raw, weighted=weighted,
                by_project=by_project, by_model=by_model)


def m(x):
    return f"{x/1e6:,.1f}M"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects-dir", default="/home/steve/.claude/projects")
    ap.add_argument("--weeks", type=int, default=0,
                    help="only report the most recent N quota weeks")
    ap.add_argument("--exclude", action="append", default=[],
                    help="substring of a transcript path to skip "
                         "(use for the auditing session itself -- gotcha #7)")
    args = ap.parse_args()

    turns, events = collect(args.projects_dir, args.exclude)
    print(f"{len(turns):,} billable claude-* turns; "
          f"{len(events)} exhaustion messages\n")

    exhausted = []
    for lo, hi in weeks(turns, args.weeks):
        hits = [t for t, _ in events if lo <= t < hi]
        end = min(hits) if hits else hi
        t = totals(turns, lo, end)
        if not t["turns"]:
            continue
        tag = (f"EXHAUSTED {end:%m-%d %H:%M}Z"
               if hits else "not exhausted (partial/under-cap week)")
        print(f"=== week {lo:%Y-%m-%d}Z .. {end:%m-%d %H:%M}Z   {tag} ===")
        print(f"    {t['turns']:,} turns   cache read {m(t['cache_read'])}  "
              f"cache write {m(t['cache_write'])}  output {m(t['output'])}")
        print(f"    RAW      {m(t['raw'])}")
        print(f"    WEIGHTED {m(t['weighted'])}")
        for label, key in (("models", "by_model"), ("projects", "by_project")):
            top = sorted(t[key].items(), key=lambda kv: -kv[1])[:5]
            print(f"    {label:9s}: " + ", ".join(
                f"{p.replace('claude-','')} {m(v)} ({100*v/t['weighted']:.0f}%)"
                for p, v in top))
        print()
        if hits:
            exhausted.append(t)

    if len(exhausted) >= 2:
        print("=== §5 discriminator: which metric is constant at 100% quota? ===")
        for label, key in (("RAW", "raw"), ("WEIGHTED", "weighted")):
            vals = [t[key] for t in exhausted]
            mean = sum(vals) / len(vals)
            var = sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)
            cv = (var ** 0.5) / mean * 100 if mean else 0
            print(f"  {label:9s} " + "  ".join(m(v) for v in vals)
                  + f"   mean {m(mean)}  CV {cv:.1f}%")
        print("\n  The metric with the markedly SMALLER CV is the one the quota\n"
              "  counts. As of 2026-08-11 they are within a point of each other,\n"
              "  so this does NOT yet discriminate: cache read is ~95% of raw and\n"
              "  ~49% of weighted, so the two co-move. Separating them needs a\n"
              "  week whose COMPOSITION is deliberately skewed -- see §5.")


if __name__ == "__main__":
    main()
