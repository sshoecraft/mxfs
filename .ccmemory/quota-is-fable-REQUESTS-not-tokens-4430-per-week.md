---
name: quota-is-fable-REQUESTS-not-tokens-4430-per-week
description: SETTLED 2026-08-15: the weekly quota counts FABLE REQUESTS (~4,430/wk, CV 3.9%), not tokens. Voids every token-efficiency conclusion; 145k cutoff bou…
metadata:
  type: project
---

# The quota counts requests, not tokens (settled 2026-08-15)

`docs/cost-audit.md` §5 asked "raw or weighted tokens?" for four weeks.
The answer is **neither**. Four consecutive credit exhaustions:

| week | exhausted | fable **requests** | fable raw | fable weighted |
|---|---|---:|---:|---:|
| 07-24 | 07-26 21:57Z | 4,244 | 2,709.4M | 383.1M |
| 07-31 | 08-03 12:50Z | 4,635 | 2,962.0M | 384.3M |
| 08-07 | 08-11 03:29Z | 4,338 | 1,049.4M | 198.1M |
| 08-14 | 08-15 20:37Z | 4,509 | 1,174.8M | 220.3M |
| CV | | **3.9%** | 49.9% | 34.7% |

**Allowance ≈4,430 Fable requests/week.** A request = distinct `requestId`;
transcript *records* overstate it ~2.2×.

## Why it is not an artefact
- Natural experiment: the 500k→145k cutoff cut tokens/week 2.5× and the week
  still died at the same request count.
- Not cadence: those weeks hit the cap at 64/57/45/141 req/h, 1.7–4.0 days in.
- No context-size weighting inside a request: the >420k-heavy week capped at
  4,244 and the all-145k week at 4,509 — big context went *further*.
- Pool is **Fable-only**, not account-wide: opus ran 2,191–9,372 req in the
  same weeks with no effect, and has never exhausted.
- Output tokens are runner-up at CV 8.5%, but output/request is ~constant so
  that is a proxy, not the metric.

## What it voids
- Every token-efficiency conclusion in the cost audit. "145k is 12.5× cheaper
  per session / 2.5× cheaper per unit work" is a true token fact worth nothing.
- **Requests per closure is flat across all four eras**: A(500k/max) 678,
  C(145k/high) 601, D(145k/high) 751. Four eras of tuning moved nothing.
  Ceiling on Fable ≈ 4,430/660 ≈ **6.7 closures/week** at any setting.
- Quota *share* lever is spent: week of 08-14, MXFS took 4,508 of the
  account's 4,509 Fable requests.
- `effortLevel high`'s −20.5% output/turn is now a **cost** signal, not a win.

## What it implies
- Per request, **bigger context is cheaper**: req/productive-action opus
  3.63 (<100k) → 2.85 → 2.40 → 2.11 → 1.99 (>420k), monotonic; fable 2.68
  (100–175k) → 2.03 → 1.59 → 2.11. The old "optimum is ~86–90k" is
  wrong-signed — shorter sessions multiply the ~5-call orientation ramp
  (~11% of a 41-request session).
- **Context-size experiments are FREE** — a 500k week and a 145k week both
  cost ~4,430 requests.
- **Opus is the only pool with headroom** (9,372 req in one week, never
  exhausted) at within 6% of Fable's req/productive-action. Availability, not
  efficiency, is the deciding factor between models.
- Bias sessions toward **fewer, larger requests**: batch parallel tool calls,
  one script instead of five shell round-trips, more thinking per turn.

## Tools
- `scripts/ccloop_request_audit.py` (NEW) — req/session, req/productive-action
  by peak-context bucket, records-per-request ratio.
- `scripts/ccloop_quota_probe.py` — per-week token totals (its "account-wide
  pool" docstring is now known wrong).
