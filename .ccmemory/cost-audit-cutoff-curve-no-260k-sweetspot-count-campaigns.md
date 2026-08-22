---
name: cost-audit-cutoff-curve-no-260k-sweetspot-count-campaigns
description: Measured cutoff curve by peak context: no sweet spot at 260k (fable 1.15x worse, opus 0.95x wash). Opus lead RETRACTED - 7 of 9 closures were one fam…
metadata:
  type: project
tags: [cost, cutoff, audit, closures, opus, effort]
---

# Cutoff curve + the Opus retraction (2026-08-11)

Supersedes the "Opus fallback is best" lead in
`cost-audit-CORRECTION-segment-eras-by-model-opus-fallback-best`.
Doc: `docs/cost-audit.md` §3.2, §3.2.1.

## RETRACTED: the Opus-fallback advantage was BATCHING
Opus era looked best (9 closures, 23.0M each, 0.308/h). But **7 of the 9 are
ONE fence/recovery family** closed together 2026-08-04: FENCED-STAGE,
VICTIM-REPLAY, RECOV-AUTH, RECOVERY-TAKEOVER, FENCE-BLOCKED,
FENCE-RESERVATION, PR-REGISTRATION (+MOUNT-INCARNATION). One campaign, one
root fix + verification sweep. Era C's 5 span FOUR unrelated subsystems.
Counting campaigns instead of rows, the eras are equivalent.

**RULE FOR ALL FUTURE OUTCOME COMPARISONS: count CAMPAIGNS, not ledger rows.**
List the closed IDs and check for family clustering first. Known family
bursts: 07-31 (5) and 08-04 (9). 08-10 (4) is genuinely independent.

## Measured cost-vs-context curve (bucket on OBSERVED PEAK, not cutoff file)
The run's `cutoff` file holds only the CURRENT value — c7ee71c6 ran sessions
1-30 at 500k under a file now reading 145000. Bucket by peak context.
Both mxfs project dirs, sessions >=20 turns, weighted per productive action:

| peak | model | sess | wt/turn | wt/prod | vs <175k |
|---|---|---|---|---|---|
| <175k | fable | 101 | 20.3k | 119k | 1.00x |
| 175-300k | fable | 5 | 26.8k | 138k | **1.15x** |
| 300-420k | fable | 5 | 38.5k | 157k | 1.31x |
| >420k | fable | 51 | 39.9k | 186k | 1.56x |
| <175k | opus | 103 | 20.2k | **108k** | 1.00x |
| 175-300k | opus | 6 | 23.0k | 103k | **0.95x** |
| >420k | opus | 14 | 40.0k | 153k | 1.41x |

## ANSWERS
- **No sweet spot at 260k.** 175-300k = 1.15x worse (fable), 0.95x wash
  (opus, n=6). No gain either model; cliff is past ~300k. KEEP 145k.
- **Opus is ~9% CHEAPER than Fable** per productive action at <175k
  (108k vs 119k). Losing Fable access costs little.
- **Opus at 500k = 1.41x worse.** Reject.
- **Effort for Opus: NO DATA EXISTS.** Only effort comparison is Fable:
  per unit quota max 0.0297 vs high 0.0377 closures/M (high +27%, because
  it burns 5.7 vs 7.6 M/h and thus buys more hours). Lean high.

## STANDING RECOMMENDATION
**145k cutoff, effort high, whichever model has credits.** The genuinely
open lever is MXFS's SHARE of the weekly quota (32% vs 66%), worth more
than all three settings combined.
