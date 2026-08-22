# MXFS session-cost audit — baselines, interventions, and re-audit plan

**Written 2026-08-07. Era C re-audit 2026-08-11. §5 SETTLED 2026-08-15 — and
the answer invalidates most of what precedes it.**

## ⚠️ READ THIS FIRST — THE QUOTA IS COUNTED IN REQUESTS, NOT TOKENS

Four consecutive credit exhaustions land at a nearly constant number of
**Fable requests** while the token totals for the same weeks vary by 2.5×:

| week (reset Thu ~04:00Z) | exhausted | fable **requests** | fable raw tok | fable weighted |
|---|---|---:|---:|---:|
| 07-24 | 07-26 21:57Z | 4,244 | 2,709.4 M | 383.1 M |
| 07-31 | 08-03 12:50Z | 4,635 | 2,962.0 M | 384.3 M |
| 08-07 | 08-11 03:29Z | 4,338 | 1,049.4 M | 198.1 M |
| 08-14 | 08-15 20:37Z | 4,509 | 1,174.8 M | 220.3 M |
| | **CV** | **3.9%** | 49.9% | 34.7% |

The natural experiment is clean: the 500k → 145k cutoff change cut tokens per
week by **2.5×**, and the week still ran out of credits at the **same request
count**. It is not a wall-clock artefact either — those four weeks reached the
cap at 64, 57, 45 and 141 requests/hour, i.e. anywhere from 1.7 to 4.0 days
in.

**The allowance is ≈4,430 Fable requests per week, ±4%, independent of how
large each request is.** Request cost is flat in context size: the
heaviest-context week (07-24, mostly >420k sessions) hit the cap at 4,244
requests and the lightest (08-14, all 145k) at 4,509 — the big-context week
came within 6% of the small-context one, inside the 3.9% noise floor and
pointing the wrong way for a size penalty.

The pool is also **Fable-only, not account-wide.** Opus requests in the same
four weeks range 2,191–9,372 with no effect on when Fable dies, and Opus has
never emitted an exhaustion message. §5.1's "account-wide pool" was inferred
from weighted totals that co-moved by coincidence.

### What that voids

- **Every token-efficiency conclusion in this document measures a currency
  that is not charged.** The "12.5× cheaper per session" and "2.5× worse per
  unit of work" figures for the 500k cutoff are real token facts and buy
  nothing.
- **Requests per closure is flat across every configuration ever run** — see
  §3.2.4. 500k/max, 145k/max, 145k/high all land in the same 600–750 band.
  Four eras of cutoff and effort tuning have not moved throughput.
- **The direction of the cutoff curve reverses.** Per *request*, bigger
  context is cheaper, not dearer (§3.2.3). §10's old item 5 — "the optimum may
  be ~86–90k, ~9% is left on the table" — is now a predicted **regression**:
  shorter sessions multiply the per-restart orientation ramp, and the tokens
  they save are free.
- **Experiments on context size are free.** Under token counting a 500k week
  cost 2.5× as much; under request counting it costs the same ~4,430
  requests. There is no longer a reason not to measure this directly.

Sections 2–5 are preserved as measured, because the token numbers in them are
correct and the reasoning built on them is instructive about how the wrong
denominator produces confident wrong answers. Read §3.2.3, §3.2.4, §5.3 and
§10 for what supersedes them.

---

**Why this file exists:** at the end of the subscription week we re-audit to
find out whether the changes actually worked. That comparison is only
meaningful against numbers measured the same way. Everything needed to
reproduce them is here.

**The 2026-08-11 headline (superseded above, kept for the record):** the
behavioural interventions worked and the token interventions did not. Sessions
now orient in **5 tool calls instead of 14** and reach for the Read tool **42%
of the time instead of 8%** — but weighted cost *per turn* is unchanged (20.3k
→ 20.1k). The orientation-ramp win is the one that still counts, because it is
denominated in tool calls, which is to say in requests.

**Read this before re-auditing.** Several conclusions below were reached,
measured, and then *refuted* — including some of the ones that sound most
plausible. Re-deriving them costs hours.

---

## 1. The re-audit, in one command

```bash
# THE metric that gates the week (added 2026-08-15). Requests per productive
# action by context bucket; requests per session; records-per-request ratio.
python3 scripts/ccloop_request_audit.py --exclude <this-session-uuid>

# Token cost. Still worth tracking as a composition signal, but it is NOT
# what the quota charges -- see the banner at the top of this file.
python3 scripts/ccloop_token_audit.py --from 'YYYY-MM-DDTHH:MM' --to 'YYYY-MM-DDTHH:MM'

# Did sessions BEHAVE differently? (handoff freshness, Read-vs-Bash,
# orientation ramp). Session numbers = session-N.prompt / sessions.log order.
python3 scripts/ccloop_behavior_audit.py --run <run-id> --from-session N

# Where did the WEEK's quota actually go, and what is the cap?
python3 scripts/ccloop_quota_probe.py --exclude <this-session-uuid>
```

The three answer different questions and all three are needed: the token
audit alone said Era C changed nothing, which was true per-turn and badly
misleading about everything else.

Use `--from/--to` (turn timestamps), **never** `--since-hours` (file mtime),
for any before/after. `--since-hours` selects whole session *files* by mtime
and then sums every turn in them, including turns outside the period. On
2026-08-07 the two methods gave **67.4M** and **58.9M** weighted for the same
run. 58.9M is the number that describes the run.

Scope the window to the ccloop run itself — from the first loop session to
the last — and nothing else. Interactive sessions in the same wall-clock
period are not part of the loop and will inflate it.

Supporting queries (per-project burn, cutoff buckets, orientation ramp,
Read-vs-Bash) are in §7; they are ad-hoc `python3 - <<EOF` transcript
parsers, not part of the script.

---

## 2. Baselines

### Era A — 500k cutoff, effort max (run c7ee71c6, Jul 28 → Aug 3, 34 sessions)

From the 2026-08-03 audit. Counted in **raw** tokens:

| | raw tokens |
|---|---:|
| output | 19,733,792 |
| cache write | 37,406,936 |
| cache read | 4,866,763,141 |
| **total** | **4,923,936,809** |

- **98.8% of raw spend is cache read.** 250:1 read-to-write ratio.
- **~145M raw tokens per session** against ~580K output per session.
- All-time at that point: 22.8B on mxfs, 6.4B on wowbot.
- This run consumed the entire week's credits and never exited.

### Era B — 145k cutoff, effort max (2026-08-07 00:15–08:02) — **THE BASELINE**

```
python3 scripts/ccloop_token_audit.py --from 00:15 --to 08:02
```

| | |
|---|---:|
| sessions | 26 |
| assistant turns | 2,900 |
| wall span | 7.8 h |
| cache read | 288.1 M |
| cache write | 9.0 M |
| output | 3.8 M |
| fresh input | 6.5 k |
| **weighted total** | **58.9 M** |
| **weighted burn rate** | **7.6 M / hour** |
| avg startup prefix | 59.0 k |
| avg peak context | 156.3 k |
| avg turns / session | 112 |
| prefix cost | 29.6% of total (3.3% write + 26.3% re-read) |

Raw per session: ~11.6M, versus **~145M** in Era A — a **12.5× reduction per
session** from the cutoff change alone.

Weighted cost split:

| bucket | raw | weight | weighted | share |
|---|---:|---:|---:|---:|
| cache read | 288.1 M | 0.10 | 28.8 M | **48.9%** |
| output | 3.8 M | 5.00 | 19.0 M | **32.3%** |
| cache write | 9.0 M | 1.25 | 11.3 M | **19.1%** |
| fresh input | 6.5 k | 1.00 | ~0 | ~0% |

**~94% of output tokens are extended thinking.** Measured indirectly:
thinking blocks appear on 48% of turns, but visible text plus tool-call
inputs account for only ~0.25M of the 3.8M output tokens. Thinking content
is redacted in the transcript, so this is a residual, not a direct count.

**During this window mxfs was 100% of burn** — zero other projects had turns
inside it. Interactive work on other projects (aimemory, aitrader, ccenv,
playerbots) all falls after 08:02 and is not loop contention.

### Era C — 145k cutoff, effort high — **MEASURED 2026-08-11**

Run c7ee71c6 sessions **174–248**, 2026-08-09 23:01 → 2026-08-10 22:33 local.
Single-variable against Era B: same cutoff, same run, same workload, only
`effortLevel` moved. 75 sessions, no interactive contamination in the window.

```
python3 scripts/ccloop_token_audit.py --from '2026-08-09T23:00' --to '2026-08-10T23:00'
```

| | Era B (max) | Era C (high) | Δ |
|---|---:|---:|---:|
| sessions | 26 | 75 | |
| assistant turns | 2,900 | 6,630 | |
| wall span | 7.8 h | 23.5 h | |
| cache read | 288.1 M | 696.2 M | |
| cache write | 9.0 M | 23.4 M | |
| output | 3.8 M | 6.9 M | |
| **weighted total** | **58.9 M** | **133.5 M** | |
| weighted burn rate | 7.6 M/h | **5.7 M/h** | −25% |
| avg startup prefix | 59.0 k | **53.8 k** | −8.8% |
| avg peak context | 156.3 k | 147.0 k | −6.0% |
| avg turns / session | 112 | 88 | −21% |
| prefix cost | 29.6% | 31.3% | +1.7 pt |

Wall span differs by 3×, so **only per-turn figures compare**:

| per turn | Era B | Era C | Δ |
|---|---:|---:|---:|
| **weighted** | **20.31 k** | **20.14 k** | **−0.8%** |
| output | 1,310 | 1,041 | **−20.5%** |
| cache read | 99.3 k | 105.0 k | +5.7% |
| cache write | 3.10 k | 3.53 k | +13.8% |
| raw | 103.8 k | 109.6 k | +5.6% |
| output share of weighted | 32.3% | **25.8%** | −6.5 pt |

**Verdict: `effortLevel max → high` is a wash.** The predicted signal fired
exactly — output share fell from 32.3% to 25.8%, and output per turn fell
20.5%, so extended thinking really did shrink. It bought nothing, because
cache read (+5.7%) and cache write (+13.8%) per turn absorbed all of it.
Weighted cost per turn moved −0.8%; raw cost per turn got 5.6% *worse*.

The −25% burn *rate* is not a saving. Era C ran 282 turns/hour against Era
B's 372: the loop got slower in wall-clock, not cheaper per unit of work.
Quoting the rate as the result is the trap this table exists to prevent.

Why cache traffic per turn rose: sessions got shorter (112 → 88 turns) while
the context they accumulate held roughly flat (97.3k → 93.2k net of prefix),
so each restart's prefix is now amortised over 21% fewer turns. Context per
turn rose 869 → 1,059 (+22%) — with less thinking per turn, each turn carries
more tool work. That also **weakens `ctx/turn` as the work proxy** for this
particular comparison (§4 validated it as flat *across cutoff buckets*, not
across effort levels); normalised that way Era C looks 18% cheaper, which is
an artefact of the proxy, not a saving. Per-turn is the honest cut.

---

## 3. Interventions — evaluated 2026-08-11

All landed 2026-08-07, commit `2ead116`. Ordered by expected impact.

| # | change | expected effect | **measured** |
|---|---|---|---|
| 1 | effort **max → high** | ~15% if quota is weighted; ~1% if raw | **WASH.** Output/turn −20.5%, output share 32.3%→25.8%, but weighted/turn −0.8% and raw/turn +5.6% |
| 2 | cutoff **500k → 145k** | 12.5× raw/session | held — Era C confirms the <200k regime |
| 3 | `memory_list` fixed | correctness; +~5.9k prefix | **works** — returns inline, 0.96 calls/session both eras, no spills |
| 4 | handoff tier | resume block 2,074 → **396** tok | **partial** — 96% FRESH, but bodies run ~1.3k tok, 3× the target |
| 5 | RULE 7 (Read tool) | Read share rises from 11% | **BEST RESULT** — 8% → **42%**; 1.9 → 8.1 Read calls/session |
| 6 | ledger split | not implemented | still not implemented; still correctness-only |

Interventions 4 and 5 target the **orientation ramp** (§4), not token count
directly. Their win is not visible in the weighted total — and indeed the
weighted total shows nothing. It is visible in §4.1.

### 3.1 What the behavioural audit actually found

```
python3 scripts/ccloop_behavior_audit.py --run c7ee71c6-... --from-session 148 --to-session 173   # Era B
python3 scripts/ccloop_behavior_audit.py --run c7ee71c6-... --from-session 174                    # Era C
```

| | Era B (148–173) | Era C (174–248) |
|---|---:|---:|
| **orientation ramp** (tool calls before 1st productive action) | median **14**, mean 16.7 | median **5**, mean 9.6 |
| Read-tool calls / session | 1.9 | **8.1** |
| Bash file-reads / session | 21.2 | 11.0 |
| Read share of file reads | 8% | **42%** |
| handoff FRESH at session start | 0% (absent) | **96%** (72/75) |
| ccloop prompt, median bytes | 17,402 | 16,436 |
| `memory_get` / session | 2.31 | 1.25 |
| `memory_search` / session | 1.23 | **0.15** |
| `memory_write` / session | 1.27 | 0.77 |

**The orientation ramp collapsed by 64%** — median 14 tool calls of
re-orienting before the first productive action, down to 5. That was the
single largest identified waste in the 08-07 audit and it is largely gone.

`memory_search` fell 8× while Read-tool calls rose 4×. Those are the same
event: RULE 7 made auto-injection fire, so sessions stopped having to search
for what the hook now hands them. Read-tool reads also concentrated on the
files that matter — `xfs_mxfs_dlm.c` 173 reads, `v5_mount.c` 74,
`disklock.c` 61 — instead of scattering across `sed -n` calls that inject
nothing.

**Where #4 fell short.** RULE 8 is being *obeyed* — 96% of sessions started
with a handoff ccloop stamped FRESH. But the projected 2,074 → 396 token
drop did not happen: measured on `session-248.prompt`, the resume block is
~1,305 tokens and the whole prompt is 15.6 KB against session-173's 18.4 KB.
Sessions are writing ~5.2 KB handoffs where the tier's arithmetic assumed
~1.6 KB. The mechanism works; the 6,000-byte cap is not the binding
constraint, and the ~900 tokens/session this was supposed to save are still
on the table. Prompt sections measured on `session-248.prompt`:

| section | bytes | ~tok |
|---|---:|---:|
| `## Current project state` (from `defects.sh`) | 8,371 | 2,092 |
| handoff body (`Active defect` → `Traps`) | 2,560 | 640 |
| wrapper / `Maintain your handoff file` / `Original task` | 1,821 | 455 |
| everything else | 833 | 208 |

### 3.2 Outcome measurement — closures, not tokens

Every metric above counts spend. None of them counts whether defects got
**fixed**, which is the only thing the loop exists to do. Cost per closure,
from `tests/criteria/OPEN_DEFECTS.json` dated dispositions.

**Segment by MODEL, not by date.** When Fable credits were exhausted on
2026-08-03 12:50Z the loop silently fell back to **Opus 5** and ran on it
until the 08-07 04:03Z reset — sessions ~36–144. A first cut of this table
segmented on date and cutoff alone, attributed that Opus work to "145k/max",
and produced an 11-closure Fable row that does not exist. Always check
`message.model` per loop session before assigning an era.

Loop sessions only (`sessions.log`), active hours = summed per-session spans:

| era | sessions | model | turns | weighted | active h | closures | **wt / closure** | **closures / active h** | burn |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|
| Era A — 500k / max | 1–30 | fable-5 | 16,591 | 632 M | 142.2 | 12 | 52.6 M | **0.084** | 4.4 M/h |
| fallback era — 145k | 36–144 | **opus-5** | 9,619 | 207 M | 29.2 | 9 | **23.0 M** | **0.308** | 7.1 M/h |
| Era B — 145k / max | 145–173 | fable-5 | 3,199 | 67 M | 8.8 | 2 | 33.5 M | **0.226** | 7.6 M/h |
| Era C — 145k / high | 174–248 | fable-5 | 6,626 | 133 M | 23.2 | 5 | 26.7 M | **0.215** | 5.7 M/h |

**The cutoff is the lever; effort is not.** 500k → 145k cut cost per closure
from 52.6 M to 26.7–33.5 M and raised closures per hour 2.6×. Fable max → high
moved cost per closure 33.5 → 26.7 M and rate 0.226 → 0.215/h — opposite signs,
both inside the noise on samples of **2 and 5**.

**Do not compare raw closure counts across eras.** Counts track duration, not
capability. Normalise per active hour, per turn, or per token.

**The loop runs at ~100% duty cycle** (Era A: 142.2 active hours in a 145-hour
span; Era C: 23.2 in 23). It stops when credits run out, not when the clock
does — so *hours of loop are not fixed*, they are `quota ÷ burn rate`. Effort
high burns 5.7 M/h against max's 7.6 M/h, so **high buys ~33% more loop hours
from the same quota.** Where wall-clock access is the scarce resource, the
cheaper-per-hour setting yields more of it, not less.

**The Opus-fallback row looks best and is not.** 9 closures at 23.0 M and
0.308/hour is the top line above, but **7 of those 9 are one fence/recovery
family** — `FENCED-STAGE`, `VICTIM-REPLAY`, `RECOV-AUTH`, `RECOVERY-TAKEOVER`,
`FENCE-BLOCKED`, `FENCE-RESERVATION`, `PR-REGISTRATION` — closed together on
2026-08-04 by a single campaign. Era C's 5 closures span four unrelated
subsystems. Counting independent campaigns rather than ledger rows, the two
eras are roughly equivalent and the Opus advantage disappears.

**Generalise that: closure counts are batchy.** One root fix can retire a
whole related family, so any era containing a family closure looks
spectacular. Before comparing eras, list the closed IDs and count *campaigns*,
not records. The 07-31 (5) and 08-04 (9) bursts are both families; the 08-10
(4) is not.

### 3.2.1 Cost vs context window — the measured curve

Bucketed on **observed peak context**, not on the `cutoff` file (which records
only the current value and is wrong for any run whose cutoff changed
mid-flight, c7ee71c6 included). Both mxfs project transcript dirs, sessions
with ≥20 turns:

| peak | model | sessions | wt/turn | wt / productive action | vs <175k |
|---|---|---:|---:|---:|---:|
| <175k | fable-5 | 101 | 20.3k | 119k | 1.00× |
| 175–300k | fable-5 | 5 | 26.8k | 138k | **1.15×** |
| 300–420k | fable-5 | 5 | 38.5k | 157k | 1.31× |
| >420k | fable-5 | 51 | 39.9k | 186k | 1.56× |
| <175k | opus-5 | 103 | 20.2k | **108k** | 1.00× |
| 175–300k | opus-5 | 6 | 23.0k | 103k | **0.95×** |
| >420k | opus-5 | 14 | 40.0k | 153k | 1.41× |

**There is no sweet spot at ~260k.** The 175–300k bucket is 1.15× worse for
Fable and a wash (0.95×, n=6) for Opus — no gain for either, and it forfeits
comparability with everything measured to date. The penalty only turns severe
past ~300k. **Keep 145k for both models.**

**Opus is ~9% cheaper than Fable per productive action at <175k** (108k vs
119k) and 1.41× vs 1.56× degraded at >420k. Losing Fable access costs little.

**Because the quota is fixed, wt/closure *is* closures-per-week inverted.**
At the ≈642M cap (§5.1), by MXFS's share of it:

| | 32% (the 08-07 week) | 50% | 66% (the 07-31 week) | 100% |
|---|---:|---:|---:|---:|
| Era A, 500k/max (52.6M) | 3.9 | 6.1 | 8.1 | 12.2 |
| Era C, 145k/high (26.7M) | **7.6** | 12.0 | **16.0** | 24.0 |
| Opus fallback (23.0M) | 8.8 | 14.0 | 18.5 | 27.9 |

MXFS's share is now the biggest untouched lever on closure throughput — worth
more than anything left in §3.

**What this cannot tell you.** Two and five closures carry ~±70% and ~±45%
counting error, so the Fable max-vs-high comparison **cannot detect anything
below roughly a 50% difference**. If max is genuinely 20% better on hard
problems — about the size that would justify its ~20% higher output cost —
this data would look exactly as it does. Absence of evidence at n=5 is not
evidence of absence. Add that 25 hours is thin for an outcome claim (the
sess240-243 AG-lock livelock arc spans more than that and is still open), and
the result is suggestive, not settled.

**Ledger dating is the weak link.** 62 of 81 records have no parseable `found`
date and 19 of 47 closures have no date, and the gaps are not random — older
records predate the convention. Recording `found` and `closed` dates on every
disposition is a cheap fix without which no future audit can measure outcomes
at all.

### 3.2.3 The same curve in requests — it points the other way

Measured 2026-08-15, `scripts/ccloop_request_audit.py`, all `-src-mxfs`
sessions with ≥20 turns. A "productive action" is the §3.1 definition (Edit /
Write, or a Bash call that builds, deploys, or drives the rig). A request is a
distinct `requestId`; one response splits into ~2.2 transcript records, so
records overstate requests by that factor and must not be used as the count.

| peak context | model | sessions | requests | **req / productive action** | req / session |
|---|---|---:|---:|---:|---:|
| 100–175k | fable | 209 | 8,627 | **2.68** | 41.3 |
| 175–300k | fable | 9 | 590 | **2.03** | 65.6 |
| 300–420k | fable | 5 | 623 | **1.59** | 124.6 |
| >420k | fable | 51 | 12,852 | **2.11** | 252.0 |
| <100k | opus | 4 | 109 | **3.63** | 27.2 |
| 100–175k | opus | 102 | 4,741 | **2.85** | 46.5 |
| 175–300k | opus | 7 | 527 | **2.40** | 75.3 |
| 300–420k | opus | 3 | 350 | **2.11** | 116.7 |
| >420k | opus | 17 | 4,340 | **1.99** | 255.3 |

Opus is monotonic across five buckets: **3.63 → 1.99, a 45% improvement from
<100k to >420k.** Fable improves to 300–420k then gives some back at >420k.
Compare §3.2.1, where the *weighted-token* version of this same table was
monotonic in the opposite direction (1.00× → 1.56× worse).

Both are true. Big sessions cost more tokens per unit of work and fewer
requests per unit of work, and only the second one is billed.

The mechanism is the orientation ramp. At 145k a session is ~41 requests and
spends a median of 5 tool calls re-orienting — **~10–12% of every session's
requests are spent rebuilding context that a longer session would still be
holding.** Doubling session length halves that overhead. §4 already measured
the same thing in the other currency and drew the opposite conclusion, because
in tokens the re-read prefix looks expensive and in requests it is free.

**Confounds, stated plainly.** The >420k rows are almost entirely Era A
(2-node workload, older code); the 100–175k rows are the 32-node era. The
`175–300k` and `300–420k` buckets are n=9 and n=5. Fleet-driving Bash calls
count as one productive action whether they touch 2 nodes or 32, which cuts
against the recent low-context rows. This table justifies **running the
experiment**, not skipping it.

### 3.2.4 Requests per closure — flat across every configuration tried

Same era windows as §3.2, recounted in requests. Era A's window contains an
Opus stretch (Fable was blocked 07-26 21:57Z → 07-31 04:16Z), so it is listed
both ways — the §3.2 table's "Era A = fable-5" label was itself wrong.

| era | window | requests | closures | **req / closure** |
|---|---|---:|---:|---:|
| A — 500k / max | 07-28 → 08-03 12:50 | 4,632 fable + 3,503 opus | 12 | 386 fable / **678 both** |
| B — 145k / max | 08-07 00:15 → 08:02 | 482 fable | 2 | **241** |
| C — 145k / high | 08-09 23:00 → 08-11 03:29 | 3,006 fable | 5 | **601** |
| D — 145k / high | 08-14 04:00 → 08-15 20:37 | 4,508 fable | 6 | **751** |

Era B is 482 requests — a 7.8-hour window, far too short to carry a closure
rate; ignore it. The three usable eras sit at 678, 601 and 751, and the
best of them is the 500k one. **Four eras of cutoff and effort tuning have
not moved requests per closure outside a ±20% band**, which is inside the
counting error §3.2 already established for n=5-and-6 closure samples.

At ≈4,430 requests/week and ~660 requests/closure, the loop's ceiling is
**≈6.7 closures/week** on Fable, whatever the settings. Era D delivered 6 with
essentially the entire Fable pool spent on MXFS.

That last point retires §8.1's lever: **quota share is no longer available.**
In the week of 08-14 MXFS took ~100% of Fable requests (4,508 of the account's
4,509). There is nothing left to reallocate on that pool.

### 3.2.5 The remaining lever is Opus, and it is large

Opus is served by a different allowance. It kept running through every Fable
exhaustion, has never emitted an exhaustion message of its own, and did
**9,372 requests in the week of 08-07** — more than twice the entire Fable
weekly allowance, in a week Fable had already died.

Per §3.2.3 Opus costs 2.85 req/productive-action at 100–175k against Fable's
2.68 (~6% worse) and beats Fable in every bucket above 300k. §3.2.1 put it ~9%
cheaper per productive action in tokens. The two models are close enough that
**availability, not efficiency, is the deciding factor** — and the "Opus
fallback era" the doc previously treated as an accident (sessions 36–144) was
the loop running on the larger pool.

This reframes §3.2's warning. The fallback era's 9 closures still deserve the
family-batching discount, but the *reason to prefer Opus* was never its
closure rate — it is that its pool did not run out.

### 3.3 Closure throughput will not shrink the ledger by itself

Era C closed 5 and found 11 — net **+6**, which is exactly the 28 → 34 open
count move between 08-07 and 08-11. Spending more buys more of *both*: running
the board is what discovers defects. The open list only shrinks when the
closed:found ratio exceeds 1, and in Era C it was **0.45**.

This is the same dynamic §6 already records as "discovery ≈ closure is why it
does not converge," and RULE 6 forbids the alternative of shortening the list
by relabeling. So the honest projection is that doubling MXFS's quota share
roughly doubles closures *and* discoveries; the ledger keeps growing until the
discovery rate falls on its own. **Budget decisions should be justified by
closure throughput, never by a promised open-count number.**

---

## 4. Supporting measurements (2026-08-07, Era B)

### Cutoff is already right — do not raise it

Cost per 1k of new context accumulated, by session peak context, across 271
sessions of history:

| peak context | sessions | **weighted per k of work** | wt/turn |
|---|---:|---:|---:|
| <200k (current) | 144 | **17.7** | 20.7k |
| 200–350k | 9 | 30.9 | 29.7k |
| 350–460k | 10 | 43.5 | 34.1k |
| >460k (Era A) | 108 | **44.6** | 40.5k |

Monotonic. 500k is **2.5× worse per unit of work** than 145k. `ctx/turn` is
flat across every bucket (839–1174), which is what validates "context
accumulated" as a work proxy — sessions do the same amount of work per turn
regardless of session length.

Modelled optimum is ~86–90k with the curve flat from 90k to 150k, so ~9% is
left on the table. Below ~90k there is no data — the shortest measured bucket
still averaged 89 turns.

### Startup prefix composition (~54–59k at turn 1)

| component | tokens | tunable |
|---|---:|---|
| Claude Code baseline (system prompt, tool schemas, skills) | ~30k | no |
| project `CLAUDE.md` | ~5.6k → ~6.6k after RULE 2c/7/8 | yes |
| ccloop prompt | 4.6–5.5k → **396** with a fresh handoff | done |
| global `CLAUDE.md` | ~2.2k | yes |
| SessionStart hook output | ~1.5k | yes |
| `memory_list` (turn 2) | was broken; now ~5.9k | done |

**Prefix economics:** anything landing at turn ~2 is re-read across ~110
remaining turns, so it costs roughly **`X × 12` weighted**. A 1k addition to
CLAUDE.md costs ~12k weighted per session. This is why prefix size matters
out of proportion to its face value.

Restart is cheaper than it looks: turn 1 shows `cw≈32.7k, cr≈21.3k` — about
21.3k of the prefix is a **cache hit carried from the previous session**, and
only ~32.7k is genuinely re-written.

### ccloop prompt decomposition (`session-173.prompt`, 18,314 B)

| section | bytes | ~tok | disposition |
|---|---:|---:|---|
| `## Current project state` (from `defects.sh`) | 8,372 | 2,093 | **keep** — computed fresh, cannot go stale |
| `## Last text from previous session` | 4,038 | 1,009 | now a fallback only |
| `## Last 20 bash commands` | 2,330 | 582 | **removed** in ccloop 0.12.0 |
| wrapper boilerplate | 1,737 | 434 | keep — small |
| `## Original task` | 694 | 173 | keep |
| headers, `## Previous session`, `## Continue` | 887 | 221 | keep |

Typical `resume.md` is ~8KB / ~2.0k tokens. Measured post-change: 2,074 →
1,284 (no handoff) → **396** (fresh handoff).

### The orientation ramp — the real waste

- **Median 16 tool calls before the first productive action** (range 2–47).
- `dlm/dlm_caw.c` read **140 times across 22 sessions** (6.4×/session);
  `xfs_mxfs_dlm.c` 36×.
- **Command overlap between sessions: 1%** (6 of 749 distinct commands).

Sessions rebuild the same mental model of the same files every time. They do
**not** repeat each other's experiments. This is why the handoff should carry
*orientation*, not history.

### ccmemory reach

*(Era B figures. Superseded by §3.1 — RULE 7 moved Read share 8% → 42%.)*

- **89% of file reads bypass the Read tool** — 19.5 Bash reads/session
  (`sed -n`, `cat`) vs 2.5 Read calls. Auto-injection fires on the other 11%.
- Per session: 2.17 `memory_get`, 0.96 `memory_search`, 0.96 `memory_list`.
- `memory_list` **failed in every session** — 59,374 chars exceeded the tool
  output cap, spilled to a file, and **0 of 24 sessions ever read the spill.**
  179 spill files on disk, none retrieved. Fixed in ccmemory 0.17.1.

---

## 5. The open question — raw or weighted? **SETTLED 2026-08-15: neither**

> **Resolution first.** Both candidate answers were wrong. The quota counts
> **Fable requests** — ≈4,430/week, CV 3.9% over four exhaustions, against
> CV 49.9% raw and 34.7% weighted for the same weeks. See the banner at the
> top of this file and §5.3. §5.1's account-wide claim is also wrong: the
> pool is Fable-only. The rest of §5 is the reasoning that failed to get
> there, kept because §5.2 correctly predicted why it couldn't.



The two audits disagree about where the money goes, and both are
arithmetically correct:

| | metric | conclusion |
|---|---|---|
| 2026-08-03 audit | **raw** tokens | 98.8% cache read; output is 1.4%; *"you are not paying for reasoning"* |
| 2026-08-07 audit | **weighted** (cr×0.10, cw×1.25, out×5.0) | output is 32.3% of cost, ~94% of it thinking |

The weights in `ccloop_token_audit.py` are **assumed price-proportional and
still have not been verified against the subscription quota formula.**

### 5.1 What 2026-08-11 established

A credit-exhaustion message is a direct observation that the quota hit 100%,
so each one is a datum. `scripts/ccloop_quota_probe.py` sums every billable
`claude-*` turn across **every** project between quota resets.

**The pool is account-wide and weekly.** It is not per-project and not
per-model: exhaustion blocks the premium model while cheaper ones keep
serving, which is why Fable 5 stops dead at each event and Opus 5 carries on.
Resets are weekly at **Thursday ~04:00Z** — observed at 07-24 04:00Z,
07-31 04:16Z and 08-07 04:03Z, i.e. 7 days apart to within 16 minutes.

Three exhaustions, totalled to the moment the credits died:

| week (reset Thu 04:00Z) | exhausted | RAW | WEIGHTED |
|---|---|---:|---:|
| 07-24 | 07-26 21:57Z | 4,419.6 M | 629.3 M |
| 07-31 | 08-03 12:50Z | 4,857.8 M | 617.1 M |
| 08-07 | 08-11 03:29Z | 4,434.8 M | 679.2 M |
| | **mean** | **4,570.7 M (CV 5.4%)** | **641.9 M (CV 5.1%)** |

**The cap is ≈642 M weighted / ≈4,571 M raw per week, ±5%.** That is new and
it is the number to budget against.

### 5.2 Why it still does not discriminate

**5.4% vs 5.1% is not a result.** Both metrics reproduce the cap equally
well, because cache read is ~95% of raw *and* ~49% of weighted — across these
three weeks the two move together, so no amount of re-totalling separates
them.

Era C did not settle it either. Its composition shift was real but too small
and pointed the wrong way: output/turn fell 20.5% while cache/turn rose, so
weighted/turn (−0.8%) and raw/turn (+5.6%) both landed within noise of "no
change." A lever that moves nothing cannot tell you what is being counted.

**What would settle it:** a week deliberately skewed in composition, not
another week of the same mix. The discriminating shape is high output share
against low cache read — many short sessions at max effort, or the reverse: a
long single-context run at low effort that reads enormously and thinks little.
If a max-effort week exhausts at ~4,571 M raw while its weighted total lands
far from 642 M, the quota is raw, and §2's cost split is wrong.

**Until then, do not spend a cycle on an intervention whose case rests on
which metric is right.** Both agree that cache read dominates and that the
prefix is re-read ~90 times a session; interventions justified by *those*
facts are safe. Intervention #1 was justified by the weighted reading alone,
and it returned nothing.

### 5.3 How it was actually settled (2026-08-15)

§5.2 asked for "a week deliberately skewed in composition." One had already
happened and nobody had looked: the 500k → 145k cutoff change cut Fable tokens
per week by 2.5× between the 07-31 and 08-07 weeks. Both weeks exhausted at
the same request count.

The measurement that settles it is a **third** candidate metric neither audit
had considered, so no amount of re-totalling the first two could have found
it. Counting distinct `requestId`s per quota week:

```
scripts/ccloop_quota_probe.py --weeks 4      # token totals per week
scripts/ccloop_request_audit.py              # request totals and req/prod
```

| metric | CV over 4 exhaustions |
|---|---:|
| fable **requests** | **3.9%** |
| fable output tokens | 8.5% |
| fable weighted | 34.7% |
| fable raw | 49.9% |
| fable + opus requests | >40% |

Output tokens are the runner-up at 8.5%, which is expected rather than
meaningful: output per request is roughly constant (~1.1–1.35k), so output
tokens are mostly a proxy for the request count. Requests are 2× tighter and
are the thing the exhaustion message is about.

**Two checks that rule out the obvious artefacts.** (1) It is not the loop's
cadence: the four weeks reached the cap at 64/57/45/141 requests per hour and
1.7–4.0 days into the week, so the constant is the count, not the clock.
(2) There is no context-size weighting inside a request: the >420k-heavy week
capped at 4,244 requests and the all-145k week at 4,509 — the big-context week
went *further* per request, and both are inside the 3.9% band.

### 5.4 The one alternative this data cannot exclude — output tokens

Raised by RULE-5 review, 2026-08-15, and it is the strongest objection to
§5.3. Cutting the window 500k → 145k slashes cache-read tokens but barely
touches **output tokens per response** — a model writes about the same
amount per turn regardless of window size. So if the meter counts output
tokens, and output-per-request is stable, you get exactly the observed
signature: requests near-constant, raw tokens swinging 2.5×.

| metric | mean | CV |
|---|---:|---:|
| fable requests | 4,431 | **3.94%** |
| fable output tokens | 12.00 M | **8.54%** |

Requests are ~2.2× tighter, but the variance ratio is 4.71 on **F(3,3)** —
**not significant at n=4.** §5.3 called output tokens "a proxy, not the
metric"; that was too confident. The honest position: the meter counts
requests *or* output tokens, and this data cannot separate them.

**Why it does not change RULE 9.** The review argued the two hypotheses
predict opposite outcomes for batching. They do not. Collapsing three turns
into one removes two responses' worth of *thinking* (~94% of output tokens,
§2) while the `tool_use` payload is unchanged — so batching reduces output
tokens as well as requests. It wins under either meter, which is why it is
safe to land ahead of the discriminator.

**Why it does change the cutoff decision.** Raising the window is justified
*only* under request metering. Under output metering it buys nothing and
still carries the long-context recall risk. That asymmetry is a second
reason (alongside §10 item 2) to leave the cutoff alone until this is
settled — and it will take a fifth week whose composition breaks the
correlation, not more re-totalling.

**What this does not establish.** Whether the request allowance is fixed or
plan-dependent; whether Opus has a much larger allowance or none at all
(observed: 9,372 in one week without exhausting, which is a lower bound, not a
cap); and whether request cost stays flat beyond 500k of context, which is
outside the measured range. Also note this is 4 observations — a fifth week
that lands far from 4,430 would reopen it.

---

## 6. Refuted — do not re-derive these

Each of these was hypothesised, measured, and killed. They are listed because
they are plausible enough to cost a session each.

| claim | verdict | evidence |
|---|---|---|
| "The 145k cutoff caused the burn spike" | **false** | 145k is 2.5× cheaper per unit work than 500k; 12.5× cheaper per session |
| "Short sessions waste turns re-orienting after each restart" | **false** | `ctx/turn` is *highest* in the <200k bucket (1174 vs 941) |
| "Sessions re-derive each other's work; the handoff must carry ruled-out hypotheses" | **false** | 1% command overlap |
| "`memory_list` costs 10.4k/session and should be dropped" | **false** | it cost 286 tokens and returned nothing — it was failing, not expensive |
| "ccmemory provides little value" | **false** | 3 load-bearing hits in one session via auto-injection and search, incl. the sess141 `i_dio_count` history that shaped the fence fix |
| "ccloop's wrapper boilerplate is ~3.7k of fat" | **false** | it is **434 tokens**; the prompt is ~85% real payload |
| "Other projects were competing for quota during the loop" | **false** | mxfs was 100% of burn inside the loop window; the rest was sequential |
| "The ccloop install failed (version reported 0.10.1)" | **false** | install was fine; `__init__.py` hardcoded a stale string. Fixed in 0.12.1 via `importlib.metadata` |
| "`dmsetup` error-target swap can rescue a wedged dm device" | **false** | circular — the swap needs the suspend lock the wedge holds. It *consumes* the escape hatch |
| "The criterion `is it production ready?` is unfalsifiable" | **false** | it is decidable; a clean system exits. Discovery ≈ closure is why it does not converge |
| "`effortLevel` max→high is the largest single lever available (~15%)" | **false** | 2026-08-11: output/turn fell 20.5% and weighted/turn moved −0.8%. Cache traffic absorbed all of it |
| "The weighted burn *rate* measures efficiency" | **false** | Era C's 7.6→5.7 M/h is a slower loop (372→282 turns/h), not a cheaper one. Per-turn is flat |
| "The weekly quota is ~350M weighted" | **false** | measured ≈642M weighted / ≈4,571M raw, from three exhaustions (§5.1) |
| "A gap in premium-model activity marks a quota-period boundary" | **false** | exhaustion blocks only the premium model; other models keep billing. Gap-detection put boundaries 38–127h apart and made both metrics look inconsistent. The reset is weekly, Thu ~04:00Z |
| "MXFS/the loop is what consumes the weekly quota" | **false** | week of 08-07: mxfs 31.7%, wowbot 50.6%; the loop itself 19.7% |
| "`ctx/turn` is a safe work proxy for any before/after" | **partly** | it is flat across *cutoff* buckets (839–1174) but moved 22% across *effort* levels, so it inflates Era C by 18%. Use per-turn |
| "max closed 11 defects vs high's 5, so max solves more" | **false, twice over** | those 11 were **Opus 5**, not Fable (fallback after the 08-03 exhaustion); and counts track duration. Fable max vs high per active hour: 0.226 vs 0.215, n=2 vs n=5 (§3.2) |
| "effort high is the cheaper choice" | **true per turn, unproven per closure** | −20.5% output/turn, but 33.5 vs 26.7 M per closure at n=2/n=5 is noise. Effort neither buys nor costs measurable throughput |
| "max gets more done in the limited wall-clock time available" | **false as stated** | the loop is credit-limited at ~100% duty cycle, so hours = quota ÷ burn rate. max burns 7.6 M/h vs high's 5.7 — high yields ~33% MORE hours from the same quota (§3.2) |
| "the loop always ran on the model it was configured for" | **false** | it silently fell back to Opus 5 for sessions ~36–144 when Fable credits died. Any era comparison must segment on `message.model` |
| "the Opus fallback era closed defects fastest, so model choice dominates" | **false** | 7 of its 9 closures are one fence/recovery family retired by a single campaign. Count campaigns, not ledger rows (§3.2) |
| "there is a happy medium around 260k" | **false** | measured: 175–300k is 1.15× worse for Fable, 0.95× (a wash) for Opus. No gain at either model; the cliff is past ~300k (§3.2.1) |
| "the run's `cutoff` file says what its sessions ran at" | **false** | it holds only the current value. c7ee71c6 ran sessions 1–30 at 500k under a file now reading 145000. Bucket on observed peak context |
| "More quota for MXFS will shrink the open-defect list" | **unsupported** | it buys closures *and* discoveries. Era C: 5 closed, 11 found, net +6 = the 28→34 move. Ratio must exceed 1, and it was 0.45 (§3.3) |
| "The quota counts tokens — the only question is raw or weighted" | **false, 2026-08-15** | it counts **Fable requests**: ≈4,430/week at CV 3.9% vs 49.9% raw / 34.7% weighted. Tokens per week moved 2.5× with no effect on when credits died (§5.3) |
| "The quota pool is account-wide across models" | **false** | Fable-only. Opus ran 2,191–9,372 requests across the same four weeks with no effect on Fable exhaustion, and has never exhausted (§3.2.5) |
| "The 145k cutoff is 2.5× more efficient per unit of work than 500k" | **true in tokens, void as a decision** | tokens are not charged. In requests per closure the eras are 678 / 601 / 751 — flat, with the 500k era best (§3.2.4) |
| "~86–90k is the modelled optimum; ~9% is left on the table" | **wrong-signed** | that model minimised tokens. Shorter sessions multiply the ~5-call orientation ramp across more restarts; per request, smaller context is *worse* (§3.2.3) |
| "Bigger context costs more per request" | **false** | the >420k-heavy week capped at 4,244 requests, the all-145k week at 4,509 — inside the 3.9% noise and pointing the other way. Context size is free (§5.3) |
| "MXFS's quota share is the biggest untouched lever" | **spent** | in the week of 08-14 MXFS took 4,508 of the account's 4,509 Fable requests. There is nothing left to reallocate on that pool (§3.2.4) |
| "effort high buys ~33% more loop hours from the same quota" | **false** | that divided a token quota by a token burn rate. The pool is requests; effort does not change how many you get, only what each one accomplishes (§3.2.4) |

---

## 7. Measurement gotchas

1. **`--since-hours` vs `--from/--to`.** File mtime vs turn timestamps. 67.4M
   vs 58.9M for the same run. Always window-scope a comparison.
2. **Scope to one project.** `~/.claude/projects/` has several active dirs.
   `-src-mxfs` alone is the loop; the others are interactive work.
3. **`memory_stats.list_tokens_actual` under-reports by 1.42×.** It counted
   10,436 where the wire payload was 14,844 tokens. Independently confirmed
   by the ccenv session (10,490 vs 14,921). Do not use it as a budget check.
4. **`ccloop --version` was lying** before 0.12.1 — a hardcoded string in
   `__init__.py` diverged from package metadata. Verify with
   `python3 -c "import ccloop; from importlib.metadata import version; ..."`
   if a result looks like a failed install.
5. **Thinking tokens are redacted** in the transcript (`thinking` field is
   empty). The ~94% figure is a residual after subtracting visible text and
   tool inputs from total output, not a direct measurement.
6. **`ps -e` / `pgrep -f` can hang forever** on a host with a wedged
   `mmap_lock` — see RULE 2c and `tools/mxfs_pgrep.sh`. This bit the audit
   itself; use `/proc/*/comm` and `/proc/*/stat`, never `cmdline`.
7. **A session's own audit turns are in its own transcript.** Auditing the
   current window from inside it inflates the result. `ccloop_quota_probe.py`
   takes `--exclude <uuid>` for exactly this; pass your own session id.
8. **Quota accounting must span every project, not just `-src-mxfs`.** The
   pool is account-wide (§5.1). This is the opposite of gotcha #2, which
   scopes a *loop* comparison to one project — different question, different
   scope. Using the mxfs-only total as "the week" understates it by 3×.
9. **Local/self-hosted models bill nothing.** `Qwen/*`, `lokeshe09/*`,
   `nvidia/*` and `<synthetic>` turns appear in the transcripts and must be
   filtered out of any quota total; only `claude-*` counts.
10. **Do not compare weighted burn *rate* across runs of different length.**
   It divides by wall-clock, so a slower loop reads as a cheaper one. Era C's
   −25% rate was entirely a −24% turn cadence. Normalise per turn.

---

## 8. Not a cost problem

Worth stating plainly so the next audit does not chase it:

- **The ledger split** (`docs/ledger-split.md`) is a *correctness* fix. It
  moves no tokens — sessions reach `OPEN_DEFECTS.json` via `defects.sh`, so
  its context footprint is the ~2k `## Current project state` block, not the
  file's 564KB.
- **`tests/logs/`** (2.3GB) was a *repo hygiene* problem, not a token one.

### 8.1 The 2026-08-11 correction — MXFS is no longer the budget

The 08-07 version of this section estimated a "~350M weekly quota ≈ 45 hours
of loop." Both halves were wrong, and the second one is the important one.

The cap is **≈642M weighted**, not 350M (§5.1). But the loop got only **23.5
hours** in the week of 08-07, because MXFS was not what spent the week:

| week | total | MXFS share | largest consumer |
|---|---:|---:|---|
| 07-24 | 629.3 M | **63.1%** (397.4 M) | mxfs |
| 07-31 | 617.1 M | **66.4%** (409.9 M) | mxfs |
| 08-07 | 679.2 M | **31.7%** (215.6 M) | **wowbot 50.6% (344.0 M)** |

Of the 08-07 week, the *loop* was 133.5M — **19.7% of the quota**. Interactive
Opus 5 work across all projects was 478.8M, **70%**.

This reframes every remaining lever in this document. Prefix trimming, handoff
tiering and effort tuning all operate on a slice that was under a third of the
week's spend, and the largest of them is worth single-digit percentages *of
that slice*. **Loop hours are now allocated by which project gets the week,
not by how efficient MXFS sessions are.** That is a scheduling decision, and
no amount of tuning in §3 substitutes for it.

The one measurement worth keeping on this axis: run
`scripts/ccloop_quota_probe.py` at the start of any week the loop must
finish something, and check the split early rather than discovering at
exhaustion that the budget went elsewhere.

---

## 9. State at the time of writing

```
2026-08-15 (Era D — §5 settled)
commit      2ead116 + this audit
ccmemory    0.17.1   (memory_list working: 92 shown of 1998, 0 load-bearing withheld)
effortLevel high     (now questionable — see §10 item 5)
cutoff      145000   (now believed too LOW — see §10 item 1)
handoff.md  working — FRESH at 96% of session starts
ledger      44 open of 97 records
quota       ≈4,430 FABLE REQUESTS/week (CV 3.9%), resets Thu ~04:00Z.
            Fable-only pool; Opus served 9,372 req in one week without dying.
            NOT tokens: the same weeks ranged 1,049–2,962M raw (CV 49.9%).
Era D       120 sessions, 10,272 records / 4,508 requests, 6 closures,
            32.5h wall, 220.7M weighted — ~100% of the account's Fable pool
last run    ended 2026-08-15 20:37Z on credit exhaustion
```

## 10. What the next audit should do

Rewritten 2026-08-15 for the request-counted quota. Ranked; every item is now
denominated in requests.

1. **Close the three unverified assumptions before changing anything else.**
   Each is under an hour (RULE-5 review, 2026-08-15):

   | assumption | status |
   |---|---|
   | a multi-tool response bills as ONE request | **VERIFIED** — 3 `Read` calls, 1 requestId |
   | the meter counts requests, not **output tokens** | **NOT SETTLED** — see §5.4 |
   | subagents bill off-pool **from a Fable parent** | **NOT VERIFIED** — the experiment's parent was Opus |

   The third is the load-bearing one for RULE 10: model *attribution* was
   verified (sonnet/haiku answered), pool *accounting from a Fable session*
   was not. Also unknown whether sonnet/haiku have their own exhaustible
   pools that heavy delegation would hit, and what happens when a subagent
   model is unavailable — does the work silently fall back onto the metered
   pool at full price? An unattended loop will not notice.

2. **Do NOT raise the cutoff to 500k yet — that is the original error
   repeating.** The affirmative case does not survive review. Requests per
   closure is flat across every configuration ever run (678/601/751), so by
   this document's own headline metric the cutoff is not a quota lever in
   either direction. And §3.2.3's 3.63 → 1.99 curve is confounded by
   **session phase**, not just era: high-peak-context sessions are long
   sessions, and long sessions are ones that had productive work to do and
   had already amortised their setup. That is selection, not causation — the
   same class of error as the token-weighting assumption this document just
   spent four weeks unwinding.

   If it is run, run it **pre-registered**: metric fixed in advance
   (closures/week), minimum n declared before looking, alternating weeks, and
   **not in the same commit as RULES 9/10** or nothing will be attributable.
   Weigh against it: degraded long-context recall on a codebase where a wrong
   edit corrupts a filesystem is an asymmetric risk, and there is no quota
   upside since requests-at-exhaustion did not move with context size.
2. **Move the loop to Opus.** Fable's pool is ~4,430 requests/week and MXFS
   already takes ~100% of it (§3.2.4), so on Fable the loop is capped at ~6.7
   closures/week no matter what. Opus did 9,372 requests in a single week
   without exhausting, at within 6% of Fable's requests per productive action
   (§3.2.5). That is the only remaining source of *more loop*.
3. **Stop optimising tokens.** Prefix trimming, handoff tiering, `effortLevel`
   and the ledger split move a currency that is not billed. Do them for
   correctness or legibility if they earn it, never for cost.
4. **Bias every session toward fewer, larger requests.** The quota charges per
   request regardless of size, so: batch independent tool calls into one
   response, prefer one script invocation over five shell round-trips, and let
   a turn do more thinking rather than splitting it. The orientation ramp
   (§3.1) is now the single most expensive habit measured — 5 calls out of ~41
   per session, ~11% of the pool.
5. **Leave `effortLevel` at high — and do not read this as evidence for
   high.** The pro-`high` case is dead: §3's "wash" verdict was scored in
   tokens, and §10's old "high buys ~33% more loop hours" divided a token
   quota by a token burn rate. But nothing replaces it with a case for `max`.
   The tempting inference — more thinking per billed request extracts more
   work per request — is unmeasured, and the one relevant observation points
   the other way: `high` ran 1,059 context/turn against `max`'s 869, i.e.
   more tool work per request. Requests-per-closure cannot resolve it either:
   the `max` arm is Era B (482 requests, 7.8 hours) and Era A (mixed
   Fable/Opus), neither usable.

   **Hold it fixed at high** so a 500k week stays comparable to Eras C and D.
   Changing model, cutoff and effort together would make the week
   uninterpretable — the same multi-variable error that muddied Era A.
6. **Date every ledger disposition** (§3.2). Unchanged and still the cheapest
   high-value item: without `found`/`closed` dates, requests-per-closure — now
   the only metric that matters — cannot be computed for future eras.
7. **Count campaigns, not ledger rows, in every outcome comparison** (§3.2).
   Unchanged: a family closure makes any era containing it look spectacular.
8. **Re-run `ccloop_request_audit.py` at each exhaustion.** Four observations
   established the ≈4,430 constant; a fifth week landing far from it would
   reopen §5, and that is worth knowing early rather than at the next
   exhaustion.

### Standing configuration recommendation (2026-08-15)

**Cutoff unchanged at 145k, effort unchanged at high, RULES 9/10 landed,
Opus if it has capacity.** Revised after RULE-5 review: the 500k case rests
on a session-phase-confounded curve and on request-metering being settled,
and neither holds (§5.4, §10 item 2). Change one thing per credit week, and
land the verifications before the behavioural changes. Basis: the quota is
~4,430 Fable requests/week (banner, §5.3); requests per closure is flat at
600–750 across every cutoff and effort tried, so no setting has ever been
shown to matter (§3.2.4); per request the context curve favours larger windows
(§3.2.3); and Opus is the only pool with headroom (§3.2.5).

The cutoff is second-order — worth 0–20% and possibly nothing. **The model is
the decision that changes throughput**: Fable caps the loop at ~6.7
closures/week at any setting, and Opus's pool is at least 2× larger. Do not
let the cutoff question delay that one.

**Superseded (2026-08-11):** "145k cutoff, effort high, whichever model has
credits" — reasoned entirely from weighted tokens per turn. It was arithmetic
about the wrong denominator, and it cost four weeks of tuning that moved
nothing.

## Related

- `scripts/ccloop_request_audit.py` — **requests** per session / productive
  action / context bucket. The metric the quota charges (added 2026-08-15)
- `scripts/ccloop_token_audit.py` — per-session token measurement
- `scripts/ccloop_behavior_audit.py` — handoff freshness, Read-vs-Bash,
  orientation ramp (added 2026-08-11)
- `scripts/ccloop_quota_probe.py` — account-wide weekly quota accounting and
  the §5 discriminator (added 2026-08-11)
- `docs/ledger-split.md` — the ledger correctness proposal
- `CLAUDE.md` RULE 2c / 7 / 8 — the behavioural changes
- ccmemory `never-pgrep-f-on-clyde-mmap-lock-wedge` — the host-wedge chain
