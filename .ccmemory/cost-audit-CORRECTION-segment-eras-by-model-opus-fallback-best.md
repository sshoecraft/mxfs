---
name: cost-audit-CORRECTION-segment-eras-by-model-opus-fallback-best
description: CORRECTION: loop silently fell back to Opus 5 when Fable credits died (sess 36-144). Segment eras by message.model. Opus era = best closure numbers o…
metadata:
  type: project
tags: [cost, audit, closures, model-fallback, correction, effort]
---

# CORRECTION + the Opus-fallback lead (2026-08-11)

Supersedes the era table in `cost-audit-closure-throughput-effort-is-free-choice`.
Doc: `docs/cost-audit.md` §3.2.

## THE BUG: eras must be segmented by MODEL, not by date+cutoff
When Fable credits died 2026-08-03 12:50Z the ccloop loop **silently fell
back to Opus 5** and ran on it until the 08-07 04:03Z weekly reset —
c7ee71c6 sessions ~36-144. An earlier table segmented on date and cutoff
alone and attributed that Opus work to "145k/max fable", inventing an
11-closure Fable row that does not exist.

**ALWAYS check `message.model` per loop session before assigning an era.**
Sessions 1-30 fable(500k) | 36-144 OPUS(145k) | 145-173 fable(145k/max) |
174-248 fable(145k/high).

## Corrected outcome table (loop sessions only, active h = summed spans)
| era | model | active h | closures | wt/closure | clos/active-h | burn |
|---|---|---|---|---|---|---|
| A 500k/max | fable | 142.2 | 12 | 52.6M | 0.084 | 4.4M/h |
| fallback 145k | **opus-5** | 29.2 | 9 | **23.0M** | **0.308** | 7.1M/h |
| B 145k/max | fable | 8.8 | 2 | 33.5M | 0.226 | 7.6M/h |
| C 145k/high | fable | 23.2 | 5 | 26.7M | 0.215 | 5.7M/h |

- Cutoff is the lever: 500k -> 145k cut cost/closure ~2x AND raised
  closures/hour 2.6x.
- Fable max vs high: 0.226 vs 0.215 clos/h, 33.5 vs 26.7M — OPPOSITE SIGNS,
  both inside noise at n=2 / n=5.

## Loop is CREDIT-limited at ~100% duty cycle — hours are not fixed
Era A 142.2 active h in a 145h span; Era C 23.2 in 23. The loop stops when
credits run out, not when the clock does. So **loop hours = quota / burn
rate**. max 7.6M/h vs high 5.7M/h => **high buys ~33% MORE loop hours from
the same quota.** Counters the intuition "max gets more done in my limited
wall-clock time" — the cheaper-per-hour setting yields MORE of the scarce
thing.

## UNCHASED LEAD: Opus-5 fallback is the best row in the table
9 closures at 23.0M each, 0.308/hour — best on BOTH metrics, and the largest
closure sample of any era (n=9). Happened by accident when Fable credits
died. If model choice dominates effort and cutoff, it reorders the whole
cost document. **Before acting: rule out that week's defects being easier.**
Also relevant to "I only have limited Fable access" — Opus is already the
automatic fallback and is not credit-limited the same way.
