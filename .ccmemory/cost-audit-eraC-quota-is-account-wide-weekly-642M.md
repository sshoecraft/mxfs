---
name: cost-audit-eraC-quota-is-account-wide-weekly-642M
description: Era C re-audit 2026-08-11: effortLevel high is a WASH; orientation ramp 14->5; quota is account-wide weekly ~642M weighted, MXFS only 32% of it.
metadata:
  type: project
tags: [cost, ccloop, quota, audit, effort, rule7, rule8]
---

# Era C cost re-audit (2026-08-11) — docs/cost-audit.md updated

Full detail in `docs/cost-audit.md`. This is the load-bearing summary.

## Tooling (all in repo, re-runnable)
- `scripts/ccloop_token_audit.py` — per-session tokens (existed)
- `scripts/ccloop_behavior_audit.py` — NEW: handoff freshness, Read-vs-Bash,
  orientation ramp. `--run <id> --from-session N [--to-session M]`
- `scripts/ccloop_quota_probe.py` — NEW: account-wide weekly quota accounting
  + the §5 raw-vs-weighted discriminator. `--exclude <own-session-uuid>`

## effortLevel max -> high is a WASH (do not re-litigate)
Era B (sess148-173, max) vs Era C (sess174-248, high), same run/cutoff/workload:
- output/turn 1310 -> 1041 (**-20.5%**), output share of weighted 32.3% -> 25.8%
- BUT weighted/turn 20.31k -> 20.14k (**-0.8%**); raw/turn +5.6%
- cache read/turn +5.7%, cache write/turn +13.8% ate the entire saving
- sessions got shorter (112 -> 88 turns) so prefix amortises over fewer turns

**TRAP:** the weighted burn *rate* fell 7.6 -> 5.7 M/h. That is NOT a saving —
turn cadence fell 372 -> 282/h. The loop got slower, not cheaper. Always
normalise per turn when run lengths differ.

**TRAP:** `ctx/turn` is a valid work proxy across *cutoff* buckets but NOT
across *effort* levels — it moved 22%, which inflates Era C by a fake 18%.

## RULE 7 / RULE 8 worked (this is the real win)
- orientation ramp: median **14 -> 5** tool calls before first productive action
- Read share of file reads **8% -> 42%**; Read calls/session 1.9 -> 8.1
- memory_search 1.23 -> 0.15/session (auto-injection now supplies it)
- handoff FRESH at 96% of session starts (was absent entirely)
- BUT handoff bodies run ~1,305 tok vs the 396 target — mechanism works,
  payload is 3x oversized. The 6000-byte cap is NOT the binding constraint.

## Quota structure (NEW, and it changes priorities)
- Pool is **account-wide across models AND projects**, resets **weekly,
  Thursday ~04:00Z** (observed 07-24 04:00Z, 07-31 04:16Z, 08-07 04:03Z).
- Cap ≈ **642M weighted / 4,571M raw** per week (3 exhaustions, ±5%).
- Exhaustion blocks only the premium model; cheaper models keep billing.
  So a gap in Fable-5 activity is NOT a period boundary — that heuristic
  gives 38-127h periods and is wrong. Use the weekly anchor.
- Local models (Qwen/gemma/nvidia/`<synthetic>`) bill nothing — filter to
  `claude-*` only.

## MXFS is no longer the budget
| week | total wt | mxfs share | biggest consumer |
|---|---|---|---|
| 07-24 | 629.3M | 63.1% | mxfs |
| 07-31 | 617.1M | 66.4% | mxfs |
| 08-07 | 679.2M | **31.7%** | **wowbot 50.6%** |

The loop itself was 133.5M = **19.7%** of the 08-07 week; interactive Opus 5
across all projects was 70%. Loop hours are now set by which project gets the
week, not by MXFS session efficiency. Prior doc estimate ("~350M quota =
~45h of loop") was wrong on both numbers.

## §5 raw-vs-weighted: still OPEN
Both metrics reproduce the cap within ±5% (CV 5.4% raw vs 5.1% weighted) —
cache read is ~95% of raw and ~49% of weighted so they co-move. Era C's
composition shift was too small to separate them. Needs a deliberately
skewed week (high output share, low cache read, or the reverse).
Meanwhile: do not justify an intervention on the weighted reading alone —
that is exactly what intervention #1 was, and it returned nothing.
