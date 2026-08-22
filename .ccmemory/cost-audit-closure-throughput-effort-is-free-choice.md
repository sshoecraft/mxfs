---
name: cost-audit-closure-throughput-effort-is-free-choice
description: Cost PER CLOSURE: cutoff halved it (56.7M->26M), effort max-vs-high indistinguishable (25.5 vs 26.7M). Raw closure counts across eras are duration ar…
metadata:
  type: project
tags: [cost, ledger, closures, effort, quota, audit]
---

# Closure throughput — the outcome half of the cost audit (2026-08-11)

Full detail: `docs/cost-audit.md` §3.2, §3.3, §10. Companion memory:
`cost-audit-eraC-quota-is-account-wide-weekly-642M`.

## The metric that matters is weighted-per-CLOSURE, not per turn
| era | turns | weighted | closures | wt/closure | clos/1k turns | critical |
|---|---|---|---|---|---|---|
| 500k / max | 17,660 | 680.0M | 12 | 56.7M | 0.68 | 8/12 |
| 145k / max | 12,942 | 280.6M | 11 | **25.5M** | 0.85 | 6/11 |
| 145k / high | 6,626 | 133.5M | 5 | **26.7M** | 0.75 | 4/5 |

- **Cutoff is the lever**: 500k -> 145k HALVED cost per closure.
- **Effort is not**: max vs high = 25.5 vs 26.7M, noise at n=11/n=5.
- Era C closures were MORE critical-weighted (80% vs 55%) — no evidence
  high effort closed easier defects.

## TRAP: never compare raw closure counts across eras
"max closed 11, high closed 5" is a DURATION artifact — 94 loop-hours vs 25.
Normalise per turn or per token. This trap was hit live in sess-audit and
the raw-count table caused it; always print denominators.

## Quota is fixed, so wt/closure IS closures-per-week inverted
Cap ≈642M weighted/week. Closures/week by mxfs share of quota:
- at 26.0M/closure: 32% share -> 7.8 | 66% -> 16.4 | 100% -> 24.7
- at 56.7M/closure: 32% -> 3.6 | 66% -> 7.5 | 100% -> 11.3
**MXFS's share of the weekly quota is now the biggest untouched lever**
(was 66% in the 07-31 week, 31.7% in the 08-07 week).

## effortLevel is a FREE CHOICE — corrected recommendation
An earlier draft said "leave effortLevel at high" reasoning from tokens per
TURN. Wrong denominator. On cost per CLOSURE max and high are
indistinguishable, so max buys no less work per unit of quota despite
costing ~20% more output/turn. **No throughput argument against max.**
n=5 cannot rule out the hard-problem benefit max is chosen for
(±45% counting error — cannot detect anything below ~50% difference).
To settle: run max at 145k for a comparable span, target ~15 closures
per arm, compare against Era C's 26.7M/closure and 80% critical mix.

## Spending more will NOT shrink the ledger
Era C: closed 5, found 11 -> net +6 open, which is EXACTLY the 28->34 move
between 08-07 and 08-11. Running the board is what discovers defects, so
more quota buys more of BOTH. Open list shrinks only when closed:found > 1;
Era C was 0.45. Same dynamic as the existing "discovery ≈ closure is why it
does not converge" finding. RULE 6 forbids the alternative (relabeling).
**Justify budget by closure throughput, never by a promised open-count.**

## Ledger dating is the weak link — FIX THIS
62 of 81 records have no parseable `found` date; 19 of 47 closures have no
date, and the gaps are not random (older records predate the convention).
Without `found`/`closed` dates on every disposition, NO future audit can
measure outcomes. Cheapest high-value fix available.
