# MXFS session-cost audit — baselines, interventions, and re-audit plan

**Written 2026-08-07. Era C re-audit 2026-08-11. §5 SETTLED 2026-08-15 — and
the answer invalidates most of what precedes it. Era E (500k) re-audit
2026-08-24 — §11; it refutes §10 item 2 and retires §3.2.4's ceiling.
Era F interim re-audit 2026-08-29 — §12: the batching and delegation rules measured, the ledger's
backfilled dates corrected, and 3.5 dark days found in the 08-21 week.
Era F closed + Era G re-audit 2026-09-08 — §15: the ±4% request constant
broke once, requests/closure halved to 98, and §16 answers why narrowing
scope to 2-node TCP did not produce a releasable product.**

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

### 2.1 Era C re-audit — the memo written at the time (2026-08-11)

The load-bearing summary of the Era C re-audit.

#### Tooling (all in repo, re-runnable)
- `scripts/ccloop_token_audit.py` — per-session tokens (existed)
- `scripts/ccloop_behavior_audit.py` — NEW: handoff freshness, Read-vs-Bash,
  orientation ramp. `--run <id> --from-session N [--to-session M]`
- `scripts/ccloop_quota_probe.py` — NEW: account-wide weekly quota accounting
  + the §5 raw-vs-weighted discriminator. `--exclude <own-session-uuid>`

#### effortLevel max -> high is a WASH (do not re-litigate)
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

#### the Read-tool and handoff rules worked (this is the real win)
- orientation ramp: median **14 -> 5** tool calls before first productive action
- Read share of file reads **8% -> 42%**; Read calls/session 1.9 -> 8.1
- memory_search 1.23 -> 0.15/session (auto-injection now supplies it)
- handoff FRESH at 96% of session starts (was absent entirely)
- BUT handoff bodies run ~1,305 tok vs the 396 target — mechanism works,
  payload is 3x oversized. The 6000-byte cap is NOT the binding constraint.

#### Quota structure (NEW, and it changes priorities)
- Pool is **account-wide across models AND projects**, resets **weekly,
  Thursday ~04:00Z** (observed 07-24 04:00Z, 07-31 04:16Z, 08-07 04:03Z).
- Cap ≈ **642M weighted / 4,571M raw** per week (3 exhaustions, ±5%).
- Exhaustion blocks only the premium model; cheaper models keep billing.
  So a gap in Fable-5 activity is NOT a period boundary — that heuristic
  gives 38-127h periods and is wrong. Use the weekly anchor.
- Local models (Qwen/gemma/nvidia/`<synthetic>`) bill nothing — filter to
  `claude-*` only.

#### MXFS is no longer the budget
| week | total wt | mxfs share | biggest consumer |
|---|---|---|---|
| 07-24 | 629.3M | 63.1% | mxfs |
| 07-31 | 617.1M | 66.4% | mxfs |
| 08-07 | 679.2M | **31.7%** | **wowbot 50.6%** |

The loop itself was 133.5M = **19.7%** of the 08-07 week; interactive Opus 5
across all projects was 70%. Loop hours are now set by which project gets the
week, not by MXFS session efficiency. Prior doc estimate ("~350M quota =
~45h of loop") was wrong on both numbers.

#### §5 raw-vs-weighted: still OPEN
Both metrics reproduce the cap within ±5% (CV 5.4% raw vs 5.1% weighted) —
cache read is ~95% of raw and ~49% of weighted so they co-move. Era C's
composition shift was too small to separate them. Needs a deliberately
skewed week (high output share, low cache read, or the reverse).
Meanwhile: do not justify an intervention on the weighted reading alone —
that is exactly what intervention #1 was, and it returned nothing.

## 3. Interventions — evaluated 2026-08-11

All landed 2026-08-07, commit `2ead116`. Ordered by expected impact.

| # | change | expected effect | **measured** |
|---|---|---|---|
| 1 | effort **max → high** | ~15% if quota is weighted; ~1% if raw | **WASH.** Output/turn −20.5%, output share 32.3%→25.8%, but weighted/turn −0.8% and raw/turn +5.6% |
| 2 | cutoff **500k → 145k** | 12.5× raw/session | held — Era C confirms the <200k regime |
| 3 | `memory_list` fixed | correctness; +~5.9k prefix | **works** — returns inline, 0.96 calls/session both eras, no spills |
| 4 | handoff tier | resume block 2,074 → **396** tok | **partial** — 96% FRESH, but bodies run ~1.3k tok, 3× the target |
| 5 | the Read-tool rule (Read tool) | Read share rises from 11% | **BEST RESULT** — 8% → **42%**; 1.9 → 8.1 Read calls/session |
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
event: the Read-tool rule made auto-injection fire, so sessions stopped having to search
for what the hook now hands them. Read-tool reads also concentrated on the
files that matter — `xfs_mxfs_dlm.c` 173 reads, `v5_mount.c` 74,
`disklock.c` 61 — instead of scattering across `sed -n` calls that inject
nothing.

**Where #4 fell short.** the queue-integrity rule is being *obeyed* — 96% of sessions started
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
| E — 500k / high | 08-21 04:00 → 08-24 08:38 | 4,270 fable + 198 opus | 21 | **203 fable / 213 both** |

Era B is 482 requests — a 7.8-hour window, far too short to carry a closure
rate; ignore it. The three usable eras sit at 678, 601 and 751, and the
best of them is the 500k one. **Four eras of cutoff and effort tuning have
not moved requests per closure outside a ±20% band**, which is inside the
counting error §3.2 already established for n=5-and-6 closure samples.

At ≈4,430 requests/week and ~660 requests/closure, the loop's ceiling is
**≈6.7 closures/week** on Fable, whatever the settings. **[RETIRED 2026-08-24
— Era E did 21 closures at 213 req/closure; see §11.]** Era D delivered 6 with
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
does not converge," and the zero-defect bar forbids the alternative of shortening the list
by relabeling. So the honest projection is that doubling MXFS's quota share
roughly doubles closures *and* discoveries; the ledger keeps growing until the
discovery rate falls on its own. **Budget decisions should be justified by
closure throughput, never by a promised open-count number.**

---

### 3.2.6 Correction: segment eras by model, not by date and cutoff (2026-08-11)

Supersedes the era table in §3.2.

#### THE BUG: eras must be segmented by MODEL, not by date+cutoff
When Fable credits died 2026-08-03 12:50Z the ccloop loop **silently fell
back to Opus 5** and ran on it until the 08-07 04:03Z weekly reset —
c7ee71c6 sessions ~36-144. An earlier table segmented on date and cutoff
alone and attributed that Opus work to "145k/max fable", inventing an
11-closure Fable row that does not exist.

**ALWAYS check `message.model` per loop session before assigning an era.**
Sessions 1-30 fable(500k) | 36-144 OPUS(145k) | 145-173 fable(145k/max) |
174-248 fable(145k/high).

#### Corrected outcome table (loop sessions only, active h = summed spans)
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

#### Loop is CREDIT-limited at ~100% duty cycle — hours are not fixed
Era A 142.2 active h in a 145h span; Era C 23.2 in 23. The loop stops when
credits run out, not when the clock does. So **loop hours = quota / burn
rate**. max 7.6M/h vs high 5.7M/h => **high buys ~33% MORE loop hours from
the same quota.** Counters the intuition "max gets more done in my limited
wall-clock time" — the cheaper-per-hour setting yields MORE of the scarce
thing.

#### UNCHASED LEAD: Opus-5 fallback is the best row in the table
9 closures at 23.0M each, 0.308/hour — best on BOTH metrics, and the largest
closure sample of any era (n=9). Happened by accident when Fable credits
died. If model choice dominates effort and cutoff, it reorders the whole
cost document. **Before acting: rule out that week's defects being easier.**
Also relevant to "I only have limited Fable access" — Opus is already the
automatic fallback and is not credit-limited the same way.


### 3.2.7 The cutoff curve, and the Opus retraction (2026-08-11)

Supersedes the "Opus fallback is best" lead in §3.2 — see §3.2.1.

#### RETRACTED: the Opus-fallback advantage was BATCHING
Opus era looked best (9 closures, 23.0M each, 0.308/h). But **7 of the 9 are
ONE fence/recovery family** closed together 2026-08-04: FENCED-STAGE,
VICTIM-REPLAY, RECOV-AUTH, RECOVERY-TAKEOVER, FENCE-BLOCKED,
FENCE-RESERVATION, PR-REGISTRATION (+MOUNT-INCARNATION). One campaign, one
root fix + verification sweep. Era C's 5 span FOUR unrelated subsystems.
Counting campaigns instead of rows, the eras are equivalent.

**RULE FOR ALL FUTURE OUTCOME COMPARISONS: count CAMPAIGNS, not ledger rows.**
List the closed IDs and check for family clustering first. Known family
bursts: 07-31 (5) and 08-04 (9). 08-10 (4) is genuinely independent.

#### Measured cost-vs-context curve (bucket on OBSERVED PEAK, not cutoff file)
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

#### ANSWERS
- **No sweet spot at 260k.** 175-300k = 1.15x worse (fable), 0.95x wash
  (opus, n=6). No gain either model; cliff is past ~300k. KEEP 145k.
- **Opus is ~9% CHEAPER than Fable** per productive action at <175k
  (108k vs 119k). Losing Fable access costs little.
- **Opus at 500k = 1.41x worse.** Reject.
- **Effort for Opus: NO DATA EXISTS.** Only effort comparison is Fable:
  per unit quota max 0.0297 vs high 0.0377 closures/M (high +27%, because
  it burns 5.7 vs 7.6 M/h and thus buys more hours). Lean high.

#### STANDING RECOMMENDATION
**145k cutoff, effort high, whichever model has credits.** The genuinely
open lever is MXFS's SHARE of the weekly quota (32% vs 66%), worth more
than all three settings combined.


### 3.3.1 Closure throughput — the memo written at the time (2026-08-11)

Full detail: §3.2, §3.3, §10.

#### The metric that matters is weighted-per-CLOSURE, not per turn
| era | turns | weighted | closures | wt/closure | clos/1k turns | critical |
|---|---|---|---|---|---|---|
| 500k / max | 17,660 | 680.0M | 12 | 56.7M | 0.68 | 8/12 |
| 145k / max | 12,942 | 280.6M | 11 | **25.5M** | 0.85 | 6/11 |
| 145k / high | 6,626 | 133.5M | 5 | **26.7M** | 0.75 | 4/5 |

- **Cutoff is the lever**: 500k -> 145k HALVED cost per closure.
- **Effort is not**: max vs high = 25.5 vs 26.7M, noise at n=11/n=5.
- Era C closures were MORE critical-weighted (80% vs 55%) — no evidence
  high effort closed easier defects.

#### TRAP: never compare raw closure counts across eras
"max closed 11, high closed 5" is a DURATION artifact — 94 loop-hours vs 25.
Normalise per turn or per token. This trap was hit live in sess-audit and
the raw-count table caused it; always print denominators.

#### Quota is fixed, so wt/closure IS closures-per-week inverted
Cap ≈642M weighted/week. Closures/week by mxfs share of quota:
- at 26.0M/closure: 32% share -> 7.8 | 66% -> 16.4 | 100% -> 24.7
- at 56.7M/closure: 32% -> 3.6 | 66% -> 7.5 | 100% -> 11.3
**MXFS's share of the weekly quota is now the biggest untouched lever**
(was 66% in the 07-31 week, 31.7% in the 08-07 week).

#### effortLevel is a FREE CHOICE — corrected recommendation
An earlier draft said "leave effortLevel at high" reasoning from tokens per
TURN. Wrong denominator. On cost per CLOSURE max and high are
indistinguishable, so max buys no less work per unit of quota despite
costing ~20% more output/turn. **No throughput argument against max.**
n=5 cannot rule out the hard-problem benefit max is chosen for
(±45% counting error — cannot detect anything below ~50% difference).
To settle: run max at 145k for a comparable span, target ~15 closures
per arm, compare against Era C's 26.7M/closure and 80% critical mix.

#### Spending more will NOT shrink the ledger
Era C: closed 5, found 11 -> net +6 open, which is EXACTLY the 28->34 move
between 08-07 and 08-11. Running the board is what discovers defects, so
more quota buys more of BOTH. Open list shrinks only when closed:found > 1;
Era C was 0.45. Same dynamic as the existing "discovery ≈ closure is why it
does not converge" finding. the zero-defect bar forbids the alternative (relabeling).
**Justify budget by closure throughput, never by a promised open-count.**

#### Ledger dating is the weak link — FIX THIS
62 of 81 records have no parseable `found` date; 19 of 47 closures have no
date, and the gaps are not random (older records predate the convention).
Without `found`/`closed` dates on every disposition, NO future audit can
measure outcomes. Cheapest high-value fix available.

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
| project `CLAUDE.md` | ~5.6k → ~6.6k after the unkillable-wedge rule/7/8 | yes |
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

*(Era B figures. Superseded by §3.1 — the Read-tool rule moved Read share 8% → 42%.)*

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

Raised by design-consult review, 2026-08-15, and it is the strongest objection to
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

**Why it does not change the request-batching rule.** The review argued the two hypotheses
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

### 5.5 The settling memo — the quota counts requests (2026-08-15)

§5 asked "raw or weighted tokens?" for four weeks.
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

#### Why it is not an artefact
- Natural experiment: the 500k→145k cutoff cut tokens/week 2.5× and the week
  still died at the same request count.
- Not cadence: those weeks hit the cap at 64/57/45/141 req/h, 1.7–4.0 days in.
- No context-size weighting inside a request: the >420k-heavy week capped at
  4,244 and the all-145k week at 4,509 — big context went *further*.
- Pool is **Fable-only**, not account-wide: opus ran 2,191–9,372 req in the
  same weeks with no effect, and has never exhausted.
- Output tokens are runner-up at CV 8.5%, but output/request is ~constant so
  that is a proxy, not the metric.

#### What it voids
- Every token-efficiency conclusion in the cost audit. "145k is 12.5× cheaper
  per session / 2.5× cheaper per unit work" is a true token fact worth nothing.
- **Requests per closure is flat across all four eras**: A(500k/max) 678,
  C(145k/high) 601, D(145k/high) 751. Four eras of tuning moved nothing.
  Ceiling on Fable ≈ 4,430/660 ≈ **6.7 closures/week** at any setting.
- Quota *share* lever is spent: week of 08-14, MXFS took 4,508 of the
  account's 4,509 Fable requests.
- `effortLevel high`'s −20.5% output/turn is now a **cost** signal, not a win.

#### What it implies
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

#### Tools
- `scripts/ccloop_request_audit.py` (NEW) — req/session, req/productive-action
  by peak-context bucket, records-per-request ratio.
- `scripts/ccloop_quota_probe.py` — per-week token totals (its "account-wide
  pool" docstring is now known wrong).

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
| "when Fable exhausts, the loop falls back to Opus and keeps running" | **false, 2026-08-29** | it did in July (sessions 36–144). In the week of 08-21 it did not: mxfs logged ZERO turns on 08-25, 08-26 and 08-27 — 3.5 of 7 days idle (§12.1) |
| "requests per productive action measures throughput" | **partly** | it also measures batching granularity — three rig calls in one response divide it by three. Era F moved req/prod −50% but req/closure only −21% (§12.5) |
| "the ledger's closed:found ratio was 0.73 in Era D+E" | **overstated** | computed on backfilled dates: 47 records carry `closed` = the `updated` proxy. Native-only, Era E is **0.571** (§12.4) |
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
   `mmap_lock` — see the unkillable-wedge rule and `tools/mxfs_pgrep.sh`. This bit the audit
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
2026-08-29 (Era F interim — §12; loop RUNNING, pool ~83% spent)
commit      6348931 + this audit
ccmemory    2,393 memories (2,150 folded); memory_list warns 18 load-bearing withheld
effortLevel high     (unchanged since Era C — hold it, §12.6 item 5)
cutoff      500000   (raised 2026-08-21; MEASURED §11, re-confirmed §12 — keep it)
the batching and delegation rules  LIVE and measured: recs/request 2.14 -> 2.99, 194 Agent calls,
            1,626 sonnet + 279 opus subagent requests served OFF the Fable pool
ledger      63 open of 173 records (44 critical) — ledger_validate CLEAN,
            but 47 `closed` dates are the `updated` PROXY (§12.4)
quota       ~4,430 FABLE REQUESTS/week (CV 3.9%, 5 observations), resets Thu ~04:00Z.
            Fable-only pool; Opus served 9,372 req in one week without dying.
last week   08-21: exhausted 08-24 08:38Z, then 3.5 DAYS DARK (no Opus fallback)
this week   08-28: 3,690 req / 3,138 productive actions in 1.57 d,
            req/prod 1.18, 23 closures, projected exhaustion 08-30 ~01:15Z
```

## 10. What the next audit should do

Rewritten 2026-08-15 for the request-counted quota. Ranked; every item is now
denominated in requests.

1. **Close the three unverified assumptions before changing anything else.**
   Each is under an hour (design-consult review, 2026-08-15):

   | assumption | status |
   |---|---|
   | a multi-tool response bills as ONE request | **VERIFIED** — 3 `Read` calls, 1 requestId |
   | the meter counts requests, not **output tokens** | **NOT SETTLED** — see §5.4 |
   | subagents bill off-pool **from a Fable parent** | **NOT VERIFIED** — the experiment's parent was Opus |

   The third is the load-bearing one for the delegation rule: model *attribution* was
   verified (sonnet/haiku answered), pool *accounting from a Fable session*
   was not. Also unknown whether sonnet/haiku have their own exhaustible
   pools that heavy delegation would hit, and what happens when a subagent
   model is unavailable — does the work silently fall back onto the metered
   pool at full price? An unattended loop will not notice.

2. ~~**Do NOT raise the cutoff to 500k yet — that is the original error
   repeating.**~~ **REFUTED AS A PREDICTION OF HARM, 2026-08-24 — see §11.**
   It was raised for the 08-21 week; nothing regressed and req/prod improved
   11.5%. The confound warnings below were all real and all came true; read
   §11.3 before quoting the result.
   Original text follows.

   **Do NOT raise the cutoff to 500k yet — that is the original error
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
   **not in the same commit as the batching and delegation rules** or nothing will be attributable.
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

**SUPERSEDED 2026-08-24 by §11.4: cutoff 500k (measured, keep it), effort
unchanged at high, the batching and delegation rules landed, Opus if it has capacity.** Original
text follows.

**Cutoff unchanged at 145k, effort unchanged at high, the batching and delegation rules landed,
Opus if it has capacity.** Revised after design-consult review: the 500k case rests
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

### 10.1 The batching and delegation rules landed; the 500k cutoff rejected on review (2026-08-15)

#### Verified this session

- **A multi-tool response bills as ONE request.** Three `Read` calls in one
  response = one requestId. the batching rule's premise. Was untested before.
- **Subagent model override works.** `model: sonnet` subagent → 3
  `claude-sonnet-5` requests; `model: haiku` → 9 `claude-haiku-4-5`
  requests; parent stayed `claude-opus-5`.
- Fleet is 32/32 up on 0.14.1 `BDEB75D40B5BE7C21C82EF6` (NOT the 0.14.2
  closure-purge build).

#### NOT verified — do not build on these

1. **Pool accounting from a FABLE parent.** The experiment's parent was
   Opus. Model *attribution* ≠ pool *debit*. Test before trusting the delegation rule
   in the loop.
2. **Whether sonnet/haiku have their own exhaustible pools.**
3. **Fallback when a subagent model is unavailable** — does the work
   silently land on the metered pool at full price? Unattended loops
   don't notice.

#### §5 REOPENED: output tokens vs requests

Cutting the window slashes cache-read but barely touches output/response.
So output-token metering produces the SAME signature.

| metric | CV over 4 exhaustions |
|---|---:|
| fable requests | 3.94% |
| fable output tokens | 8.54% |

Variance ratio 4.71, **F(3,3) — not significant at n=4.** The earlier
"output is just a proxy" dismissal was too confident.

**the batching rule survives either way**: batching removes 2 responses' worth of
thinking (~94% of output) while the tool_use payload is unchanged, so it
cuts output tokens too. **The cutoff change does NOT survive** — raising
the window only pays under request metering.

#### 500k cutoff REJECTED (was recommended earlier in the same session)

- Requests/closure is flat across every config ever run (678/601/751) — by
  the headline metric the cutoff is not a lever in either direction.
- The 3.63→1.99 req/productive-action curve is confounded by **session
  phase**: high-peak sessions are LONG sessions, which are ones that had
  productive work and had already amortised setup. Selection, not
  causation — same error class as the token-weighting assumption.
- Asymmetric risk: degraded long-context recall on a codebase where a wrong
  edit corrupts a filesystem.
- If run: pre-registered, metric fixed in advance, alternating weeks, NOT
  in the same commit as the batching and delegation rules.

#### The sharpest review catch (now in the delegation rule)

**A capped report makes the WEAKER model select which evidence survives,
and selection is a conclusion wearing evidence's clothes.** Verbatim
`file:line` excerpts look compliant with the zero-defect bar while silently omitting the line
that mattered. Worst case is negatives: haiku's "no matches" (wrong regex?
wrong subtree?) becomes an evidence-backed "defect not present".
Mitigations written into the delegation rule: report exact commands + **pre-truncation
totals**; re-verify disposition-critical negatives in the parent; a
subagent may NEVER widen or retry a timed-out run (the derived-budget rule) — a helpful weak
model re-running a flaky test until green launders a defect away.

Also: every agent definition must embed the budget, unkillable-wedge and inspect rules verbatim — subagents
inherit nothing from CLAUDE.md, and a haiku agent running `pgrep -f` wedges
clyde unattended.

#### Open items worth more than any of this
- **Post-exhaustion behaviour**: what does the loop do for the 3-5 days
  between exhaustion and Thursday reset? If "nothing", that dwarfs every
  lever here.
- **Restart economics as a line item**: sessions/week × ~5-request ramp.
- Audit CLAUDE.md for every rule motivated by TOKEN cost — all are now
  candidates for reversal.

## 11. Era E re-audit (2026-08-24) — the 500k week, measured

**The week 2026-08-21Z → exhausted 2026-08-24 08:38Z. Cutoff 500k, effort
high. This is the pre/post §10 item 2 asked for, and it was NOT run
pre-registered — see the caveats before quoting the headline.**

### 11.1 The measurement

```
python3 scripts/ccloop_request_audit.py --from '2026-08-21T04:00' --to '2026-08-24T08:38' --exclude <this-session>
python3 scripts/ccloop_quota_probe.py --weeks 6 --exclude <this-session>
```

| | Era D — 145k / high | Era E — 500k / high | Δ |
|---|---:|---:|---:|
| window | 08-14 04:00 → 08-15 20:37 | 08-21 04:00 → 08-24 08:38 | |
| wall to exhaustion | **1.7 d** | **3.2 d** | +88% |
| sessions (mxfs) | 115 | **37** | −68% |
| requests (mxfs) | 4,582 | 4,468 | −2.5% |
| requests / session | 39.8 | **120.8** | +204% |
| productive actions | 1,705 | **1,878** | **+10.1%** |
| **requests / productive action** | **2.69** | **2.38** | **−11.5%** |
| records / request | 2.29 | 2.14 | −6.6% |
| fable weighted tokens (week) | 220.3 M | 381.4 M | +73% |
| ledger closures on the fable pool | 6 | **21** | **3.5×** |
| **net open-queue change** | — | **+12 (44→56)** | **diverged — §11.6** |
| **requests / closure** | **751** | **213** | **−72%** |

Requests-per-productive-action by observed peak context, Era E, fable:

| bucket | sess | reqs | prod | req/prod |
|---|---:|---:|---:|---:|
| 0–100k | 1 | 12 | 5 | 2.40 |
| 175–300k | 9 | 443 | 136 | 3.26 |
| 300–420k | 6 | 714 | 284 | 2.51 |
| **>420k** | **19** | **3,101** | **1,370** | **2.26** |

The largest bucket is the cheapest per unit of work, and it carries 73% of
the week's requests. §3.2.3's direction survives contact with a deliberately
big-context week.

### 11.2 What actually moved, and why

The request budget did not change (4,468 vs 4,582 — inside the ±4% noise
floor the banner established over five weeks now). Everything gained came
from spending those requests differently:

- **78 fewer session restarts.** At §3.1's measured 5-call orientation ramp
  that is ~390 requests, ~8.7% of the pool, returned to work. The +10.1% in
  productive actions is that number almost exactly.
- **Wall-clock to exhaustion nearly doubled** (1.7 d → 3.2 d) at the same
  request count, because a 500k session does more per request, not because
  it was throttled.
- **Tokens rose 73% and cost nothing.** Exactly as the banner predicts. This
  is the first week that spent the token budget freely on purpose.

### 11.3 Caveats — do not quote 3.5× without these

1. **Closures are counted in ledger rows, which §10 item 7 forbids.** Era E's
   21 rows span roughly 5–6 campaigns (rman/foreign-replay, AGI/AGI-freecount,
   fence/PR, compat `bio_add_vmalloc_chunk` + `kvrealloc`, terminal-replay);
   Era D's 6 rows span ~3 (the D-488 family, D-503, D-0130). Campaign-normalised
   the gain is nearer **2×** than 3.5×.
2. **~~Era E is a closure-harvest phase: 0 new defects found.~~ WRONG,
   CORRECTED 2026-08-24 — see §11.6.** That reading came from counting the
   ledger's `found` field, which is **not a date field**: only 16 of 142
   records carry an ISO date, 54 carry `sessNNN` strings and 62 are empty.
   Any date-range query over `found` returns garbage. The ledger actually
   *grew by 45 records* over 08-15 → 08-24. Era E was not a harvest phase;
   it discovered at least as fast as it closed. §10 item 6 ("date every
   ledger disposition") is now load-bearing, not housekeeping.
3. **Not single-variable.** the batching and delegation rules (batching + delegation) were in force
   for Era E and were landing during Era D. §10 item 2's "not in the same
   commit as the batching and delegation rules or nothing will be attributable" was not honoured.
4. **Era D's week is understated by its own boundary.** Fable died 08-15
   20:37Z but the week ran to 08-21, and 12 further closures landed
   08-19/08-20 on Opus. Whole-week, Era D = 18 closures and Era E = 21 with
   Opus still unspent.

### 11.4 Verdict — on the cutoff question only. §11.6 is the one that gates the project.

**The cutoff is not a no-op, and §10 item 2's "do not raise it" is refuted as
a prediction of harm.** Nothing got worse: no measured metric regressed, and
req/prod improved 11.5% on a mechanism (fewer orientation ramps) that is
independent of the phase confound. Requests-per-closure leaving the 600–750
band for the first time is real but is the weakest of the three signals.

The honest reading: **the cutoff bought ~10%, mechanically and repeatably,
and the phase bought the rest.** Keep 500k. It is free under request
metering and the only downside ever argued against it — degraded long-context
recall — did not show up as a defect-quality signal in this week's 21
dispositions.

**§3.2.4's ceiling is retired.** "≈6.7 closures/week on Fable whatever the
settings" was computed from a 751 req/closure sample of n=6. Era E did 21.

### 11.5 Banner table, fifth observation

| week (reset ~04:00Z) | exhausted | fable **requests** (mxfs) | fable weighted |
|---|---|---:|---:|
| 08-21 | 08-24 08:38Z | 4,270 | 381.4 M |

The ≈4,430 ± 4% constant holds for a fifth week — measured mxfs-scoped, and
mxfs was 96% of the week's weighted spend. Nothing in §5 reopens.

**Superseded by §15.1**: the sixth week (08-28) came in at 5,808, +31% outside
the band. The constant is now six-of-seven, not seven-of-seven.

### 11.6 The number that actually matters: the ledger DIVERGED

Everything in §11.1–11.4 measures *throughput*. The project's goal is not
throughput, it is **an empty open queue** (zero-defect bar) — and by that measure Era
E did not make progress. It went backwards.

| date | open | records | source |
|---|---:|---:|---|
| 2026-08-07 | 28 | — | §3.3 |
| 2026-08-11 | 34 | — | §3.3 |
| 2026-08-15 | 44 | 97 | §9 state block |
| **2026-08-24** | **56** | **142** | this audit |

Over 08-15 → 08-24: **33 records resolved, 45 records added, open +12.**
Era E's own window (08-21 → 08-24) resolved 21 and left 17 open records
freshly touched.

**closed : found ratio**

| era | closed | found | ratio |
|---|---:|---:|---:|
| C (08-07→08-11) | 5 | 11 | **0.45** |
| D+E (08-15→08-24) | 33 | 45 | **0.73** |

The ratio improved by 62% and is **still below 1**, which is the only
threshold that matters. Below 1 the queue grows no matter how fast the loop
runs; the 3.5× closure gain bought a slower divergence, not convergence.

**Composition is worse than the count.** 39 of the 56 open records are
`critical`, 12 `high`. There is no tail of trivia to clear — the queue is
almost entirely release-blocking under the zero-defect bar, and `tests/suite/open_defects.sh`
will keep the board red until every one of them is disposed.

**What this does and does not change:**

- It does **not** reverse §11.4. Nothing regressed; 500k is still free and
  still the right setting. But "did the cutoff help" and "are we converging"
  are different questions and only the first one got a yes.
- It confirms §3.3 exactly as written: *"the ledger keeps growing until the
  discovery rate falls on its own... budget decisions should be justified by
  closure throughput, never by a promised open-count number."* Era E is the
  second consecutive era where that held.
- **The cutoff was never the binding constraint, and neither is the model.**
  At 21 closures and ~35 discoveries per week, convergence needs the
  closed:found ratio above 1. Doubling the loop (the Opus lever, §3.2.5)
  doubles *both* sides and moves the ratio approximately nowhere. Config
  tuning cannot fix this; only a fall in the discovery rate can, and that
  arrives when the fleet stops finding new failure modes — i.e. when the
  campaign has covered the space, not when the loop runs faster.

**The metric to gate future weeks on is the closed:found ratio, not requests
per closure.** Requests per closure says how efficiently the pool is spent.
Only the ratio says whether the project is getting closer to shipping.

### 11.7 Era E — the memo written at the time (2026-08-24)

Week 2026-08-21Z → exhausted 2026-08-24 08:38Z. Cutoff **500k** (raised
2026-08-21 against §10 item 2's advice), effort high, the batching and delegation rules in force.

##### Measured (mxfs-scoped, `ccloop_request_audit.py`, this session excluded)

| | Era D 145k | Era E 500k | Δ |
|---|---:|---:|---:|
| wall to exhaustion | 1.7 d | 3.2 d | +88% |
| sessions | 115 | 37 | −68% |
| requests | 4,582 | 4,468 | −2.5% |
| req/session | 39.8 | 120.8 | +204% |
| productive actions | 1,705 | 1,878 | +10.1% |
| **req / productive action** | **2.69** | **2.38** | **−11.5%** |
| recs/request | 2.29 | 2.14 | −6.6% |
| fable weighted tok | 220.3 M | 381.4 M | +73% |
| ledger closures (fable pool) | 6 | 21 | 3.5× |
| **req / closure** | **751** | **213** | **−72%** |

Era E fable by peak-context bucket — **the >420k bucket is the CHEAPEST**
(2.26 req/prod) and carries 73% of the week's requests: 0-100k 2.40 /
175-300k 3.26 / 300-420k 2.51 / >420k 2.26. §3.2.3's direction survives a
deliberately big-context week.

##### Mechanism (the part that is NOT confounded)

78 fewer session restarts × §3.1's 5-call orientation ramp ≈ **390 requests
(~8.7% of the pool) returned to work** — which is the +10.1% in productive
actions almost exactly. Tokens rose 73% and cost nothing, as the
request-metering banner predicts.

##### Caveats — never quote 3.5× bare

1. Ledger ROWS, which §10 item 7 forbids. Era E's 21 rows ≈ 5-6 campaigns
   vs Era D's 6 rows ≈ 3. Campaign-normalised the gain is nearer **2×**.
2. Era E is a **closure-harvest phase**: 0 defects FOUND in the window vs 5
   in Era D's. Phase is confounded with cutoff.
3. Not single-variable — the batching and delegation rules were landing across the boundary,
   exactly what §10 item 2 said would destroy attribution.
4. Era D's own week ran to 08-21; 12 more closures landed 08-19/20 on OPUS
   after fable died 08-15. Whole-week Era D = 18, Era E = 21 with Opus
   unspent.

##### Dispositions recorded in the doc

- §10 item 2 "do NOT raise the cutoff to 500k" — **refuted as a prediction
  of harm**. Nothing regressed. Keep 500k; it is free under request metering.
- §3.2.4's "≈6.7 closures/week on Fable whatever the settings" — **RETIRED**.
  It was 751 req/closure off n=6. Era E did 21 at 213.
- Banner's ≈4,430 ±4% request constant — **holds for a fifth week** (4,270
  mxfs-scoped; mxfs was 96% of the week's weighted spend).
- Standing recommendation now: **500k / high / the batching and delegation rules / Opus if it has
  capacity.** The model is still the untried lever (§3.2.5).

##### Gotcha for the next audit

`scripts/ccloop_request_audit.py` defaults to `--project -src-mxfs` even
with no flag — it does NOT give an account-wide count. Use `quota_probe`
for the per-project split.


### 11.8 The §11.6 correction, as written at the time (2026-08-24)

User pushback 2026-08-24: throughput gains are not the point; **closing the
ledger and shipping is.** Measured, and the throughput story does not survive
as an answer to that question.

##### Open-queue trajectory

| date | open | records |
|---|---:|---:|
| 2026-08-07 | 28 | — |
| 2026-08-11 | 34 | — |
| 2026-08-15 | 44 | 97 |
| **2026-08-24** | **56** | **142** |

Over 08-15 → 08-24: **33 resolved, 45 added, open +12.** Era E's own window
(08-21 → 08-24) resolved 21 and left 17 open records freshly touched.

**39 of the 56 open are `critical`, 12 `high`.** No trivia tail to clear —
the whole queue is release-blocking under the zero-defect bar.

##### closed : found

| era | closed | found | ratio |
|---|---:|---:|---:|
| C (08-07→08-11) | 5 | 11 | 0.45 |
| D+E (08-15→08-24) | 33 | 45 | 0.73 |

Improved 62%, **still below 1** — the only threshold that matters. Below 1
the queue grows however fast the loop runs. The 3.5× closure gain bought a
slower divergence, not convergence.

##### The load-bearing conclusion

**Config tuning cannot fix this, and neither can the Opus lever.** At ~21
closures and ~35 discoveries/week, doubling the loop doubles BOTH sides and
moves the ratio approximately nowhere. Convergence arrives only when the
discovery rate falls on its own — i.e. when the campaign has covered the
failure space, not when the loop runs faster. This is §3.3 holding for a
second consecutive era.

**Gate future weeks on the closed:found ratio, not requests per closure.**
req/closure says how efficiently the pool is spent; only the ratio says
whether MXFS is getting closer to shipping.

##### MEASUREMENT TRAP — the ledger `found` field is NOT a date field

Only **16 of 142** records carry an ISO date in `found`; 54 carry `sessNNN`
strings, 62 are empty. A date-range query over `found` silently returns
near-zero and looks like a real finding. It produced a false "Era E found 0
new defects, it was a closure-harvest phase" caveat in the first cut of §11.3.

Use `updated` + status for closures, and the **net open count** for
discovery. §10 item 6 ("date every ledger disposition") is now load-bearing,
not housekeeping — without it the only metric that gates the project cannot
be computed per-era.

Also: `scripts/ccloop_request_audit.py` defaults to `--project -src-mxfs`
even with no flag; it never gives an account-wide count.

## 12. Era F interim re-audit (2026-08-29) — batching + delegation, measured

**INTERIM. Measured 2026-08-29 17:42Z, 1.57 days into the 08-28 week, with
the loop still running and ~740 requests left in the pool. Projected
exhaustion 2026-08-30 ~01:15Z at 1.89 d wall. The next audit MUST re-run
these commands over the closed window `--from '2026-08-28T04:00' --to
'<exhaustion>'` and replace this section's numbers; everything here is a
partial week and the closure counts especially will move.**

```
python3 scripts/ccloop_request_audit.py --from '2026-08-28T04:00' --exclude <this-session>
python3 scripts/ccloop_quota_probe.py --weeks 4 --exclude <this-session>
python3 scripts/ccloop_delegation_audit.py --since '2026-08-28T04:00'
```

### 12.1 The 08-21 week did not end at exhaustion — it went dark

Fable died 2026-08-24 08:38Z. mxfs then logged **zero turns on 08-25, 08-26
and 08-27**, and resumed only at the 08-28 04:00Z reset. Turns per UTC day,
mxfs, fable+opus:

| day | fable turns | opus turns |
|---|---:|---:|
| 08-22 | 3,432 | 12 |
| 08-23 | 3,043 | 61 |
| 08-24 | 1,725 | 128 |
| 08-25 → 08-27 | **0** | **0** |
| 08-28 | 5,994 | 0 |
| 08-29 (to 17:42Z) | 4,978 | 40 |

**3.5 of the 7 days were idle.** §10 item 2 ("move the loop to Opus") was
never acted on, and the fallback that carried sessions 36–144 in July did not
happen this time — the loop simply stopped. This is now the largest single
lever in this document, larger than anything in §3: Opus's pool is at least
9,372 requests/week and has never exhausted, so the dark half of the week is
available at no cost to the Fable pool.

### 12.2 The measurement

| | Era D — 145k | Era E — 500k | **Era F — 500k, the batching and delegation rules live** |
|---|---:|---:|---:|
| window | 08-14 04:00 → 08-15 20:37 | 08-21 04:00 → 08-24 08:38 | 08-28 04:00 → **08-29 17:42 (partial)** |
| wall measured | 1.7 d (to exhaustion) | 3.2 d (to exhaustion) | **1.57 d (running)** |
| sessions (mxfs) | 115 | 37 | 33 |
| requests (mxfs fable) | 4,582 | 4,468 | **3,690** (~83% of pool) |
| productive actions | 1,705 | 1,878 | **3,138** |
| **requests / productive action** | 2.69 | 2.38 | **1.18** (−50% vs E) |
| records / request | 2.29 | 2.14 | **2.99** (+40%) |
| requests / session | 39.8 | 120.8 | 111.8 |
| burn rate | — | ~55 req/h | **97.9 req/h** |
| ledger closures | 6 | 21 | **23** |
| **requests / closure** | 751 | 203 | **160** (−21% vs E) |

By observed peak context, Era F, fable:

| bucket | sess | reqs | prod | req/prod |
|---|---:|---:|---:|---:|
| 175–300k | 1 | 51 | 54 | 0.94 |
| 300–420k | 2 | 134 | 87 | 1.54 |
| **>420k** | **30** | **3,505** | **2,997** | **1.17** |

The >420k bucket is 95% of the week's requests and remains the cheapest per
unit of work. §3.2.3's direction survives a third consecutive week.

**`records/request` is the batching telltale.** It measures how many transcript
records one billed response emits, i.e. how many tool calls were batched into
it. It sat at 2.07–2.32 every day of Era E and jumped to 3.08 / 2.87 on the
first two days of Era F. That is the request-batching rule finally biting, and it is the
mechanism behind the req/prod halving.

### 12.3 Delegation went from zero to real

`scripts/ccloop_delegation_audit.py --since '2026-08-28T04:00'`, 27 fable
sessions / 3,090 requests:

| | |
|---|---:|
| Agent calls made | **194** |
| subagent runs | 160 sonnet, 34 opus |
| **subagent requests served off the Fable pool** | **1,626 sonnet + 279 opus** |
| mechanical requests (all tool calls delegable) | 1,361 (44%) |
| chains of ≥3 consecutive mechanical requests | 153 |
| **still saveable by one Agent call per chain** | **444 (14% of all requests)** |

The 2026-08-22 delegation audit measured **0 Agent calls** (`docs/cost-audit.md`).
~1,900 requests of mechanical work now run off-pool.

Largest remaining categories, fractional by request:

| category | requests | share | delegable |
|---|---:|---:|---|
| text/listing | 998.0 | 32.3% | **yes** |
| Read | 543.1 | 17.6% | no (the Read-tool rule/10) |
| harness-run | 412.4 | 13.3% | **yes** |
| Edit | 211.1 | 6.8% | no |
| no-tool (text/thinking only) | 166.0 | 5.4% | no |
| Agent | 124.7 | 4.0% | — |
| ledger | 117.7 | 3.8% | **yes** |
| build-deploy | 102.4 | 3.3% | **yes** |
| fleet-ssh | 72.2 | 2.3% | **yes** |

`text/listing` is the single biggest line in the budget and is flagged
delegable. That is the next 10% if anyone wants it.

### 12.4 the queue-integrity rule landed — and exposed that the old ratios were wrong

`tools/ledger_validate.py`: **173 records, all dates present and
well-formed.** The gate works. The *provenance* is another matter — the
backfill had to invent structure for records that never carried it:

| `date_provenance` | records |
|---|---:|
| `closed` = the `updated` field — **PROXY, not the measured disposition date** | 47 |
| `opened` = iso-prefix of the original `opened` string | 46 |
| `opened` = earliest ISO date in the record's prose — DERIVED | 37 |
| (none — natively dated) | 35 |
| `opened` = iso-prefix of `found` | 16 |
| `updated` = `opened` (record never had one) | 15 |

**71 of 110 disposed records show `opened` == `closed`.** A same-day
find-and-fix is real and common in this loop, but not at 65%; that number is
the backfill collapsing two unknown dates onto one known one.

So every closed:found ratio computed before 08-28 is measured partly on
proxies. Recomputed on natively-dated records only:

| era | closed (native) | found (native) | **ratio** |
|---|---:|---:|---:|
| E (08-21 → 08-28) | 12 | 21 | **0.571** |
| **F (08-28 → 08-29)** | **23** | **22** | **1.045** |

§11.6 reported Era D+E at 0.73 on mixed proxied data; the native-only cut of
Era E alone is **0.571**. Era F is the **first window ever measured above
1.0**, and it is the first window whose dates were all recorded live rather
than reconstructed.

**Do not celebrate yet.** The directly-counted queue still grew:

| date | open | critical | records |
|---|---:|---:|---:|
| 2026-08-24 (§11.6) | 56 | 39 | 142 |
| **2026-08-29** | **63** | **44** | **173** |

Era F opened 29 records in its window — 22 filed live plus 7 legacy records
that the backfill dated into it — and closed 23. The ratio crossing 1 is on
the native subset; the queue as counted is **+7 open, +5 critical**. Both
statements are true and the second one is the one the zero-defect bar cares about.

### 12.5 Caveats — do not quote 1.18 without these

1. **Half the req/prod gain is accounting granularity, not throughput.**
   Batching three independent rig calls into one response divides req/prod by
   three without doing more work. The batching-independent check is
   requests/closure, which improved **21%** (203 → 160), not 50%. Read the
   1.18 as real efficiency *and* finer batching, in roughly equal parts.
2. **1.57 days is not a week.** 23 closures carries ~±20% counting error, and
   §10 item 7 still applies: campaign-normalise before comparing. Era F's 23
   rows span roughly 6–8 campaigns (TCP authority ledger, single-node
   authority, free-publish/D-0351, bootstrap owner-claim, ICREATE/purge pace,
   quarantine/replay).
3. **Not single-variable, for the third era running.** the request-batching rule batching and
   the delegation rule delegation both went from near-zero to fully adopted inside this
   same window, on top of the 500k cutoff carried over from Era E. Nothing
   here attributes the gain to one of them.
4. **The projection is a projection.** 97.9 req/h × 7.6 h remaining is a
   straight-line extrapolation from a loop that has been running 1.6 days.

### 12.6 What next week's audit must do

Ranked, and every item is denominated in requests or in the ratio.

1. **Close this window properly.** Re-run §12's three commands with
   `--to <exhaustion timestamp>` and replace §12.2. Add the sixth
   observation to the banner table (§11.5) — the ≈4,430 ± 4% constant now has
   five confirmations and Era F will be the sixth.
2. **Fill the dark days.** The measured cost of not running Opus after Fable
   dies is **3.5 idle days out of 7**. Before tuning anything else, decide
   whether the loop continues on Opus at exhaustion. This is worth
   approximately a doubling of weekly closures and needs no configuration
   experiment to justify.
3. **Gate on closed:found, natively dated only.** Filter out every record
   whose `date_provenance` names a proxy or a derivation before computing the
   ratio. The mixed number is not comparable across eras and made Era E look
   28% better than it was.
4. **Stop optimising requests-per-productive-action.** At 1.18 the floor is
   ~1.0 and the whole remaining headroom is 15%. The `text/listing` category
   (32.3% of requests, delegable) is the last cheap win; after that this axis
   is finished.
5. **Do not change cutoff or effort.** Three eras at 500k/high with no
   regression. Changing them now would make the the batching and delegation rules attribution
   question permanently unanswerable.
6. **Check whether the sonnet/haiku subagent pool has a ceiling.** Era F
   pushed 1,626 sonnet requests off-pool in 1.6 days. §10 item 1's third
   assumption — "subagents bill off-pool from a Fable parent" — is still
   listed as NOT VERIFIED, and the loop is now leaning on it hard. If that
   pool exhausts or silently falls back to the metered one, an unattended
   loop will not notice.

### 12.7 Era F interim — the memo written at the time (2026-08-29)

Measured 2026-08-29 17:42Z, 1.57 days into the 08-28 quota week, loop still
running, ~740 of ~4,430 Fable requests left. The full write-up is §12; this is the memo written at the time.

#### The finding nobody was looking for: 3.5 dark days

Fable exhausted 2026-08-24 08:38Z (Era E). mxfs then logged **ZERO turns on
08-25, 08-26 and 08-27**. No Opus fallback — the loop simply stopped until the
08-28 04:00Z reset. Section 10 item 2 ("move the loop to Opus") was never acted
on, and the July fallback behaviour (sessions 36-144) did not repeat.

**This is now the largest lever in the whole document.** Opus's pool is at
least 9,372 req/week and has never exhausted. Half the calendar week is free
capacity sitting unused.

#### Era F numbers (1.57 d, PARTIAL — re-run at exhaustion)

| | Era E 500k | Era F 500k + the batching and delegation rules |
|---|---:|---:|
| requests (mxfs fable) | 4,468 | 3,690 (~83% of pool) |
| productive actions | 1,878 | 3,138 |
| req / productive action | 2.38 | **1.18** |
| records / request | 2.14 | **2.99** |
| closures | 21 | 23 |
| req / closure | 203 | **160** |
| burn | ~55 req/h | **97.9 req/h** |

Projected exhaustion 2026-08-30 ~01:15Z, 1.89 d wall (Era E was 3.2 d).

`records/request` is THE batching telltale — it counts tool calls batched into
one billed response. It sat at 2.07-2.32 every day of Era E and jumped to
3.08 / 2.87 in Era F. the batching rule is what moved it.

#### Delegation went from zero to real

194 Agent calls; **1,626 sonnet + 279 opus subagent requests served OFF the
Fable pool**. The 2026-08-22 delegation audit measured 0 Agent calls. Still
saveable: 153 chains of >=3 consecutive mechanical requests = 444 req (14%).
Biggest single category is `text/listing` at 32.3% of requests, flagged
delegable — that is the last cheap win on this axis.

#### the ledger-date rule landed, and it corrected the old ratios

`tools/ledger_validate.py`: 173 records, all dates present and well-formed.
But the backfill had to invent structure: **47 records carry `closed` = the
`updated` field (an explicit PROXY, not the measured disposition date)**, 37
`opened` values were derived from prose, only 35 are natively dated. 71 of 110
disposed records show opened == closed, which is the backfill collapsing two
unknown dates onto one.

Recomputed on natively-dated records only:

| era | closed | found | ratio |
|---|---:|---:|---:|
| E (08-21 -> 08-28) | 12 | 21 | **0.571** |
| F (08-28 -> 08-29) | 23 | 22 | **1.045** |

Section 11.6 reported Era D+E at 0.73 on mixed proxied data. Era F is the
first window ever measured above 1.0 AND the first whose dates were all
recorded live. **Always filter on `date_provenance` before computing the
ratio.**

But the directly-counted queue still GREW: open 56 -> 63, critical 39 -> 44,
records 142 -> 173. Both statements are true; the zero-defect bar cares about the second.

#### Caveats — do not quote 1.18 bare

1. Half the req/prod gain is accounting granularity. Batching three
   independent rig calls into one response divides req/prod by three without
   doing more work. The batching-independent check is req/closure, which moved
   only -21% (203 -> 160), not -50%.
2. 1.57 days is not a week; 23 closures is ~+/-20% counting error. Those 23
   rows span roughly 6-8 campaigns — campaign-normalise (section 10 item 7).
3. Not single-variable, third era running: the batching and delegation rules both went from
   near-zero to fully adopted in the same window, on top of the carried-over
   500k cutoff.

#### Reproduce

```
python3 scripts/ccloop_request_audit.py --from '2026-08-28T04:00' --to '<exhaustion>' --exclude <this-session>
python3 scripts/ccloop_quota_probe.py --weeks 4 --exclude <this-session>
python3 scripts/ccloop_delegation_audit.py --since '2026-08-28T04:00'
python3 tools/ledger_validate.py
```

NOTE: `ccloop_quota_probe.py` mis-detected an exhaustion at 08-28 04:00Z and
truncated the new week to 7 turns. Do not trust its per-week row for a week
that is still running; use `ccloop_request_audit.py` with an explicit
`--from/--to` instead.

#### Next week's audit: the ranked list is section 12.6

1. Close the window properly (re-run with `--to <exhaustion>`), add the sixth
   banner observation.
2. Fill the dark days — decide whether the loop continues on Opus at
   exhaustion. Worth ~a doubling of weekly closures, no experiment needed.
3. Gate on closed:found, natively-dated records only.
4. Stop optimising req/prod — floor is ~1.0, only 15% left.
5. Do not change cutoff or effort (would destroy the batching and delegation rules attribution).
6. Verify the sonnet/haiku subagent pool has no ceiling — section 10 item 1's
   third assumption is still NOT VERIFIED and the loop now leans on it hard.


### 12.8 The delegation audit that preceded it (2026-08-22, sess390)

Script: `scripts/ccloop_delegation_audit.py` (`--files <uuid-prefixes>` / `--run <id> --from-session N` / `--since`; `--per-session`). Full analysis + proposal: `docs/delegation.md`.

#### Numbers (5 Fable loop sessions 08-21 20:23Z → 08-22 12:09Z, 721 requests)
- text/listing 23.6%, fleet-ssh 20.6%, Read 15.0%, harness-run 12.1%, Edit 12.1%, build-deploy 5.0%, dmesg 2.5%, ledger 2.3%, transcript 1.0%.
- **65% of requests purely mechanical; 50% (364) inside chains of ≥3 consecutive mechanical requests** = saveable by one Agent call per chain. 08-15 era: 42% / 22%. `Agent` calls: 0 in every Fable session since the delegation rule landed.
- Arithmetic: an Agent call is 1 request, so delegating a single (already batched) Bash saves nothing; savings = chain length − 1. Target chains, not calls.
- VERIFIED from a Fable parent (this session, rig-runner 4-node poll): subagent transcript = `claude-sonnet-5`, 2 requestIds, 11.5 s; parent spent 1 Fable request. Pool DEBIT still only provable at next exhaustion (Fable count at exhaustion < 4,430 by the subagent total ⇒ subagents debit the pool).

#### Why sessions don't delegate (evidence in docs/delegation.md §3)
1. the delegation rule is optional language that argues against itself, at line 435.
2. Direct conflict with "WAIT IN THE FOREGROUND / never background" — Agent IS background work; no stated exception.
3. the Read-tool rule + "never delegate reading" pull locate+read into the parent; locating (24%) is never named as delegable.
4. Roster = 2 narrow agents; log-sweeper is opus; no agent for board-triage, build-deploy, tree-scout, transcript-miner, ledger-reader, orient.
5. ccloop session prompt / state.sh never mention agents.
6. No measurement feeding back (fixed: the audit script).
7. No enforcement — every behaviour change that stuck here was a hook/gate.

#### Proposal (NOT applied; each item needs the user's yes)
5.1 PreToolUse deny-hook on parent Bash for always-chain shapes (fleet loop, run.sh, build+deploy, jsonl parsing, ≥3-command tree sweeps) → names the agent. Open q: discriminate parent vs subagent (PreToolUse input has no agent_type; test transcript_path, else SubagentStart marker).
5.2 Roster, all sonnet (haiku for ledger): rig-runner, board-triage, build-deploy, tree-scout, log-sweeper→sonnet, transcript-miner, ledger-reader, orient.
5.3 the delegation rule rewrite as a trigger table + explicit Agent-is-the-sanctioned-background exception + "chains not calls".
5.4 state.sh adds roster + previous session's delegation audit line; cost-audit §1 gets the script.
5.5 KPIs in requests + flags/1k Fable requests (forensic text moves to sonnet context → expect flag rate down).


### 12.9 The ledger date schema, enforced in three layers (2026-08-24)

User directive after the Era E audit produced a confidently wrong finding
("Era E discovered 0 new defects") by date-range-querying the ledger's
`found` field, which is ISO-dated on only 16 of 142 records. The ledger had
actually grown by 45 records that week.

##### The schema

| field | required | format |
|---|---|---|
| `opened` | always | bare ISO `YYYY-MM-DD` |
| `closed` | iff status is a disposition | bare ISO `YYYY-MM-DD` |
| `updated` | always | bare ISO `YYYY-MM-DD` |
| `status` | always | exactly `OPEN` / `FIXED AND VERIFIED` / `DISPROVED` |
| `severity` | always | `critical` / `high` / `major` / `minor` |

A date field holds a date and nothing else. `2026-08-04 sess80` is NOT a
date. Prose provenance goes in `found`, which nothing ever parses as a date.

##### Three enforcement layers (all landed and tested)

1. `tools/ledger_validate.py` — the gate. Exit 1 + `id: field: reason` lines.
2. `tests/suite/open_defects.sh` — **FAILS the board on a schema violation**,
   independently of the open count, same standing as an unreadable ledger.
3. `tools/hook_ledger_guard.sh` — PostToolUse hook in `.claude/settings.json`
   (matcher `Edit|Write|MultiEdit|NotebookEdit`), blocks the write with exit 2.

##### PATH INDEPENDENCE — the thing that was nearly got wrong

First cut hardcoded `/src/mxfs` in all three AND **failed open** when the
path did not resolve. User caught it: "what if they clone it to
/jimmys_stuff/mxfs?" A guard that silently no-ops in a clone is worse than
no guard — ledger and board both look healthy while dates rot.

Now: each resolves the repo from its OWN location
(`readlink -f "$0"` -> dirname -> ..), the hook validates **the ledger path
from the payload** (so a second checkout checks its own file), settings.json
uses `"$CLAUDE_PROJECT_DIR/tools/hook_ledger_guard.sh"`, and open_defects.sh
honours `$MXFS_LEDGER` with `/src/mxfs` only as a last-resort fallback (the
rig NFS-mounts /src and runs that very file, so it resolves there anyway).

**All three fail CLOSED**: missing validator, missing python3, or unreadable
ledger blocks the write / fails the board. Verified in a real clone at
`/tmp/jimmys_stuff_*/mxfs`: dirty clone ledger -> exit 2; clean clone ledger
-> exit 0 and the criterion moves on to the open-count gate; validator
removed -> exit 2 naming both paths it searched.

##### Hook mechanics

**Payload arrives as JSON on STDIN, not in env vars** — an earlier inline
`$CLAUDE_TOOL_INPUT` version was simply wrong. Unparseable payload exits 0
so it can never block an unrelated file. Exit 2 = block + stderr fed back.

##### Backfill — `tools/ledger_backfill_dates.py`

Applied 2026-08-24: 280 violations -> 45. Derives ONLY what a record already
states, records every derived value in `date_provenance`, writes literal
`UNKNOWN` where nothing supports a date. Never invents a date — a wrong date
silently corrupts the closed:found ratio; a missing one announces itself.
Also canonicalised 13 status spellings, moved 85 prose fragments into
`found`. Verified lossless: 142 records, 56 open, 86 disposed, ids identical,
no field dropped. Backup: `tests/criteria/OPEN_DEFECTS.json.backup`.

Top level is a DICT `{"_comment": [...20 strings...], "defects": [...]}` —
`_comment` is a LIST, so "first list found" heuristics grab the wrong thing.

##### OUTSTANDING — 28 records, 36 fields still `UNKNOWN`

Board stays red on schema until hand-filled. Mostly old
`FIXED AND VERIFIED` records missing `closed`. Five are OPEN and missing
`opened`: D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO,
D-READDIR-PEER-CACHED-DIR-PACE, D-RECOV-ADVANCE-UNBOUNDED-RETRY,
D-RECOV-ZERO-EPOCH-DESCRIPTOR-AUTHORITY-UNPROVEN,
D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531.
Full list: `python3 tools/ledger_backfill_dates.py` (report mode).

## Related

- `scripts/ccloop_request_audit.py` — **requests** per session / productive
  action / context bucket. The metric the quota charges (added 2026-08-15)
- `scripts/ccloop_token_audit.py` — per-session token measurement
- `scripts/ccloop_behavior_audit.py` — handoff freshness, Read-vs-Bash,
  orientation ramp (added 2026-08-11)
## 13. Ledger-health audits (2026-09-04)


### 13.1 Ship-envelope audit — the user-requested strategy change

User asked: stop fixing every defect at 32 nodes; find the largest N where integrity+stability can be guaranteed, ship 1.0 there, then scale to 32.

#### Findings
- Ledger 212 filed / 87 OPEN (59 crit). Weekly opened 3,38,31,27,40,34,39 vs closed 0,28,14,11,24,33,15; running open 3->87. closed:found 0.59. Queue grew every week. Almost every filing came from 32/caw runs.
- Classification of the 87 by smallest N at which the mechanism fires:
  - core any N>=2: 52 (foreign replay, fencing/PR, SB lost-update x3, inode-cluster publish, stale shell, unmount drain/hang, whole-cluster restart, inact-cert, samenode waiter bit, ...)
  - scale-amplified promoted to core (reachable at 4 by mechanism; GPT concurred): 8 (AGIFC-408, DLMSCALING-380, ICLUS-0517, MASS-FALSE-DEATH-482, NOINO-474, CASCADE-474, DIRVIEW-SESS25, FENCE-RECONVERGE-376)
  - pace present at 4: 3 (SHARED-DIR-CREATE-PACE: ladder shows 2.2-3.5x at P=4 vs 6.5x at 32; READDIR-PEER 1.2s; TMPFILE-CHURN)
  - re-measure at 4 (32-only numbers): 3 (CONVOY-0281, CRASH-BARRIER-401, CAW-WIRE-UNLOCK)
  - deferred by product scoping: 20 (14 TCP, 3 dirshard, 2 host, RSYNC-AG-SHARING-388)
  - meta: 1 (MATRIX-UNMEASURED)
  => 4-node CAW-only gate = 66 records; node count removes ~20, not ~60.
- Boards: 2/caw 09-02 26P + dirent_publish_integrity FLAKY (2 genuine FAIL/11); 8/caw 09-02 fence_during_write FAIL (victim never rejoined, 7/8 for 160s, 12 BLOCKED) — UNEXPLAINED, no matching ledger record (rig formats 32 slices so not D-0523); 16/caw 09-02 all green; 32/caw 09-04 0.70.18 25P, crash_consistency FLAKY = 9 genuine FAIL/11 (should read FAIL); 4/caw was stale (08-01) — fresh board launched this session.
- Harness facts: criteria.json stores NO build identity per cell; verify_ship.sh is a separate older gate topping out at 16 nodes on a 16-VM pool; mkfs sets MXFS_FORMAT_F_DIRSHARD by DEFAULT with no opt-out flag; MXFS_MAX_NODES=64 / 64 HB slots compiled ceiling.

#### Recommendation (GPT review agreed, with corrections folded in)
- 1.0 profile: 4 nodes, CAW only, sharding off at mkfs, homogeneous proto_gen, agcount>=N and slices>=2N, qualified write-through storage. Each rule must be ENFORCED IN CODE (refusal before writable activation) or it is relabeling.
- 4 not 2: 2 cannot reach successor-dies-mid-takeover, double victim w/ survivors, 2-2 partition, shared-AG double-victim replay. 8 adds pressure, no new topology.
- "Guarantee" needs: enforced envelope + harness truthfulness (evidence-of-run, break-each-harness-once) + deterministic fault matrix at 4 (11 fence crash points, double victims, replay refusal/unwind/intents, waiter cancel, slot reuse, unmount-during-publish, whole-cluster loss x5 phases; 10 clean reps) + durability (physical target, 100 cold restarts, fsck+oracle) + 100 consecutive clean 4-node laps + 168h stress + weekly 32-node canary.
- Proposed ledger re-org (NEEDS USER OK, schema change): add `scope` + `min_nodes` fields; ./defects.sh --scope; open_defects gates 4/caw on in-scope set only.

Artifact: scratchpad mxfs_ship_envelope_audit.html (published).


### 13.2 Auditing the closed side of the ledger (sess480)

After six vacuous-PASS harnesses were found in two sessions, the obvious worry is
that some of the 106 `FIXED AND VERIFIED` records were closed on evidence that
measured nothing. `tools/closure_evidence_audit.py` screens for that offline —
no rig time. It follows each record's cited evidence and scans for signatures.

#### Result on 198 records (106 closed)

| bucket | n | % |
|---|---|---|
| SIGNATURE | 2 | 1.9% |
| NO_CITED_ARTIFACT | 71 | 67.0% |
| DIR_EVIDENCE_ONLY | 8 | 7.5% |
| SCREENED_CLEAN | 25 | 23.6% |

**Both SIGNATURE hits were verified by hand and are false positives.** Both are
`REFUSAL_PRESENT:ABORT:` on logs that D-RECOV-ADVANCE-UNBOUNDED-RETRY and
D-CROSSNODE-OPEN-UNLINK-DATA-LOSS cite as *superseded re-run attempts*, which
the records label as such; the actual closure evidence is elsewhere and was
confirmed present (`tests/evidence/20260829T045853Z_radv_takeover` contains the
claimed `P238-RECOV-TAKEN slot=31`).

**So: no confirmed contaminated closure.** But the coverage number is the real
finding — only ~33% of closed records cite an artifact that can be followed at
all (log-only 5, dir-only 8, both 22, neither 71). Many of the 71 close on
prose-quoted direct measurement, which is a legitimate form (e.g.
D-MOUNT-INCARNATION-CONSTANT-ZERO quotes a raw `dd` of the heartbeat sector) —
but it is not machine-auditable, so this screen speaks for a third of the closed
ledger and is silent about the rest.

#### The tool had two vacuity bugs of its own — both instructive

1. **`INSTANT_DONE_WITH_PASS` fired on five records wrongly.** It took the first
   and last compact `20260829T124123Z` timestamp anywhere in the file — but chain
   logs write START/DONE in ISO form (`2026-08-29T12:39:54Z`) and use the compact
   form only inside evidence-DIRECTORY names. It was measuring the gap between
   two directory stamps and calling an 8-minute run instant. Now anchors on the
   START and DONE lines.
2. **It followed only `.log` paths**, which is why 79 records first appeared to
   cite nothing. Much closure evidence is a timestamped evidence *directory*.

A screening tool that cries wolf gets ignored, which costs more than the misses.
Two heuristics were tightened accordingly: a refusal annotated "expected"/"by
design" within two lines is skipped (before/after chains deliberately fail their
pre-fix arm), and `got=0 want=N` counts only when the line is **not** already
prefixed `FAIL`/`ERROR` — a gate that fired and scored the run down is the system
working, not a vacuous PASS.

#### How to use it

    tools/closure_evidence_audit.py [--verbose] [--status OPEN|"FIXED AND VERIFIED"]

Treat `SCREENED_CLEAN` as a screening result only. Absence of a signature is not
presence of a measurement.

## 14. Whole-history closed:found, natively dated (measured 2026-09-04)

§11.6 asked for the ratio to be gated on and §13 asked for it natively dated.
Both conditions now hold: the ledger is schema-clean at 201 of 201 records,
every `opened` and every `closed` parses, and no date is a backfilled proxy for
`updated`. The cumulative open count derived week by week lands exactly on the
84 that `open_defects.sh` reports, so the series is internally consistent.

| ISO week | found | closed | ratio | cumulative open |
|---|---|---|---|---|
| 2026-W30 | 3 | 0 | 0.00 | 3 |
| 2026-W31 | 38 | 28 | 0.74 | 13 |
| 2026-W32 | 31 | 14 | 0.45 | 30 |
| 2026-W33 | 27 | 11 | 0.41 | 46 |
| 2026-W34 | 40 | 24 | 0.60 | 62 |
| 2026-W35 | 34 | 33 | 0.97 | 63 |
| 2026-W36 *(partial, 4 of 7 days)* | 28 | 7 | 0.25 | 84 |
| **whole history** | **201** | **117** | **0.582** | |

**The ratio has never exceeded 1 in any week, so the open queue has grown in
every week of the project's life.** That is the whole finding, and it is the
one number that decides whether a zero-open-defect bar is reachable: at a
sustained 0.58 the queue diverges regardless of how many sessions run, because
each unit of closure work uncovers more than it retires.

Read the shape, not just the level. W33 → W35 is a genuine improvement —
0.41, 0.60, 0.97 — and W35 came within one record of break-even. W36's 0.25 is
a partial week and should not be compared against completed ones until it
closes. So the honest statement is that closure throughput was converging
toward break-even and has not yet crossed it, not that the project is
stagnant.

Two further properties of the open queue, both measured the same way:

- **Severity is top-heavy: 55 critical, 22 high, 5 major, 2 minor.** Two thirds
  of everything open is critical. Either the scale is being applied generously
  or the remaining work is genuinely all load-bearing; that distinction is
  worth settling, because a severity field that is 65% critical carries almost
  no ordering information and the queue is worked in severity order.
- **The queue is actively worked, not abandoned.** Median age of an open record
  is 12 days (p25 5, p75 24, max 41), 13 of 84 were touched in the last two
  days, and only 4 have gone 30+ days untouched: `D-MATRIX-UNMEASURED`,
  `D-DIRVIEW-NONCONVERGE-SESS25`, `D-RELOAD-FREED-ADOPT-BOGUS-IMODE`,
  `D-FENCED-VICTIM-MAY-REREGISTER`. Staleness is not what is holding the
  ratio down; discovery outpacing closure is.

---

- `scripts/ccloop_quota_probe.py` — per-week Fable **request** and token
  totals, bounded by the terminal exhaustion, and the §5 discriminator (added
  2026-08-11; request counting and the boundary fixes 2026-09-08, §15.2). Its
  "account-wide pool" docstring is known wrong — the pool is Fable-only.
- `scripts/ccloop_delegation_audit.py` — where each Fable request went by kind
  of work, chain lengths, Agent calls and off-pool subagent requests
- `docs/ledger-split.md` — the ledger correctness proposal
- `CLAUDE.md` the unkillable-wedge rule / 7 / 8 — the behavioural changes
- ccmemory `never-pgrep-f-on-clyde-mmap-lock-wedge` — the host-wedge chain

---

### 14.1 The measurement as recorded (2026-09-04)

Earlier estimates of this ratio were contaminated: 47 records carried `closed`
as a backfilled proxy for `updated`. That is no longer true. The ledger is now
**schema-clean at 201/201** — every `opened` and `closed` parses, statuses are
exactly the three legal strings — and the week-by-week cumulative open count
lands exactly on the 84 that `open_defects.sh` reports. The series is real.

| ISO week | found | closed | ratio | cum open |
|---|---|---|---|---|
| W30 | 3 | 0 | 0.00 | 3 |
| W31 | 38 | 28 | 0.74 | 13 |
| W32 | 31 | 14 | 0.45 | 30 |
| W33 | 27 | 11 | 0.41 | 46 |
| W34 | 40 | 24 | 0.60 | 62 |
| W35 | 34 | 33 | 0.97 | 63 |
| W36 (partial, 4/7 days) | 28 | 7 | 0.25 | 84 |
| **all** | **201** | **117** | **0.582** | |

#### What this means for the zero-open-defect bar

**At a sustained 0.58 the queue diverges** — running more sessions does not
approach the bar, because each unit of closure work uncovers more than it
retires. The bar is reachable only if the ratio holds above 1 for a sustained
stretch, and it has not done so in a single week yet.

**But read the shape, not only the level.** W33 → W35 is 0.41, 0.60, 0.97 — a
real improvement that came within one record of break-even. W36 is a partial
week and must not be compared against completed ones. The honest statement is
*converging toward break-even, not yet across it* — not "stagnant".

#### Two other properties of the open queue

- **65% of open records are `critical`** (55 critical, 22 high, 5 major, 2
  minor). A severity field that is two-thirds one value carries almost no
  ordering information, and the queue is worked in severity order. Worth
  settling whether the scale is applied generously or the remainder is
  genuinely all load-bearing.
- **The queue is worked, not abandoned.** Median open age 12 d (p25 5, p75 24,
  max 41); 13 of 84 touched in the last two days; only **4** untouched for 30+
  days — `D-MATRIX-UNMEASURED`, `D-DIRVIEW-NONCONVERGE-SESS25`,
  `D-RELOAD-FREED-ADOPT-BOGUS-IMODE`, `D-FENCED-VICTIM-MAY-REREGISTER`.
  Staleness is not the constraint; discovery outpacing closure is.

Re-derive rather than quote: the numbers
move every week, and the point is the trend line, not any single value.

## 15. Era F closed + Era G re-audit (2026-09-08) — two weeks measured

Supersedes §12, which was explicitly interim (1.57 d into the 08-28 week).
Both weeks below are closed windows, bounded by the exhaustion that actually
ended them.

```
python3 scripts/ccloop_quota_probe.py --weeks 3 --exclude <this-session>
python3 scripts/ccloop_request_audit.py --project=-src-mxfs --from ... --to ...
python3 scripts/ccloop_delegation_audit.py --since ... --until ...
python3 scripts/ccloop_behavior_audit.py --run 140e6b67-fcc2-463c-a250-0452f9187f5d
```

### 15.1 The ±4% request constant broke — once, upward

| week (reset Thu 04:00Z) | terminal exhaustion | wall | fable **requests** | fable weighted |
|---|---|---:|---:|---:|
| 07-24 | 07-26 21:57Z | 2.7 d | 4,244 | 383.1 M |
| 07-31 | 08-03 12:50Z | 3.4 d | 4,635 | 384.3 M |
| 08-07 | 08-11 03:29Z | 4.0 d | 4,338 | 198.1 M |
| 08-14 | 08-15 20:37Z | 1.69 d | 4,509 | 220.3 M |
| 08-21 | 08-24 08:38Z | 3.19 d | 4,250 | 381.4 M |
| **08-28** | **09-02 19:55Z** | **5.66 d** | **5,808** | **859.6 M** |
| **09-04** | **09-09 01:29Z** | **4.90 d** | **4,627** | **628.7 M** |

Six of the seven sit at **4,437 ± 4.0%** — the constant is intact and this
week (4,627) is inside it. The 08-28 week is a genuine outlier at **5,808,
+31% above the band**, and the cause is not established. Two candidates, both
unproven: the allowance moved, or the account was served past its cap during
the `fable-5` → `fable-5-1` transition, which straddles exactly that week
(58% of its weighted spend on fable-5, 39% on fable-5-1). It is not a
measurement artefact — the week's 5,808 distinct `requestId`s were counted the
same way as every other week's.

**Do not treat 5,808 as the new allowance.** One observation, immediately
followed by a week back inside the old band. Plan against ~4,430.

### 15.2 The 08-28 week was mis-read as 3,679 by taking the first refusal

`ccloop_quota_probe.py` ended a week at the *first* "out of usage credits"
message inside it. That is wrong twice over, and both bugs are now fixed:

- An exhaustion **35 seconds after the reset** (08-28 04:00:35Z) is the
  previous week's refusal still being retried. Taking it as the boundary made
  the 08-28 week report **7 turns** for a week that ran 5.66 days.
  Fix: `--boundary-grace-min` (default 45).
- An **isolated mid-week refusal** (08-29 17:37Z, one message, at 3,679
  requests) was followed by 2,129 more Fable requests in the same week. It is
  a shorter-horizon limit, not the weekly cap. Fix: `--terminal-quiet-min`
  (default 30) — an exhaustion counts as the cap only if no Fable request
  follows it.

§12 measured that week at 1.57 d wall and projected exhaustion at 1.89 d. It
actually ran **5.66 d**, three times the projection, because the refusal §12
projected from was not the cap.

### 15.3 The two weeks, against Era E

Ledger columns are aligned to the **quota** week (Thu 04:00Z → Thu 04:00Z), so
they are directly comparable to the request columns. They therefore differ
slightly from §14's ISO-week series, which is aligned to Mon–Sun.

| | Era E — 08-21 | Era F — 08-28 | **Era G — 09-04** |
|---|---:|---:|---:|
| window | 08-21 04:00 → 08-24 08:38 | 08-28 04:00 → 09-02 19:55 | 09-04 04:00 → 09-09 01:29 |
| wall to exhaustion | 3.19 d | 5.66 d | 4.90 d |
| fable requests | 4,250 | 5,808 | 4,627 |
| requests / productive action | 2.38 | **1.14** | 1.42 |
| Agent calls | 0 | 194 | **230** |
| subagent requests (off-pool) | 0 | 1,905 | **2,419** |
| mechanical share of fable requests | — | 44% | **36%** |
| ledger found | 28 | 61 | 50 |
| ledger closed | 22 | 30 | **47** |
| **closed : found** | 0.79 | 0.49 | **0.94** |
| **requests / closure** | 193 | 194 | **98** |
| net change in open queue | +6 | +31 | **+3** |

**Requests per closure halved.** 98 is the best figure this document has ever
recorded — §3.2.4's "flat across every configuration, 600–750" is now three
eras out of date, and the improvement since is 7×. Batching (the request-batching rule) and
delegation (the delegation rule) are the only changes that fit the timeline, and the
mechanical share of Fable requests falling 44% → 36% while Agent calls rose
194 → 230 is consistent with delegation being the larger part of it.

**Requests per productive action rose 1.14 → 1.42, and that is not a
regression.** Era G ran a third of its sessions below 420k context (27 of 61,
against 4 of 60 in Era F), and req/prod is monotonic in context size — 1.33 at
>420k, 1.68 at 175–300k, 3.75 at 100–175k. The >420k bucket alone was 1.32 in
Era G against 1.12 in Era F; the rest is composition.

**Still divergent, but barely.** 0.94 is the best closure ratio ever measured
and the queue still grew, 88 → 91. Every completed week in the project's life
has a ratio below 1 (§14).

### 15.4 Days that produced nothing

mxfs turns per UTC day, both weeks:

| day | fable | opus | |
|---|---:|---:|---|
| 08-28 | 5,994 | 0 | |
| 08-29 | 4,978 | 56 | |
| 08-30, 08-31 | **0** | **0** | idle, credits live |
| 09-01 | 992 | 0 | |
| 09-02 | 5,807 | 90 | exhausted 19:55Z |
| 09-03 | 0 | **840** | **Opus fallback — §12.1's lever, working** |
| 09-04 | 6,077 | 1,378 | |
| 09-05 | 3,895 | 0 | |
| 09-06, 09-07 | **0** | **0** | idle, credits live |
| 09-08 | 2,992 | 0 | |
| 09-09 | 487 | 79 | exhausted 01:29Z |

Two different losses, and they need different fixes:

- **Dark after exhaustion**: 08-28 week 1.34 d, 09-04 week 2.10 d — down from
  3.5 d in the 08-21 week. §12.1's lever was pulled exactly once, on 09-03,
  for 840 Opus turns. It did not repeat after the 09-09 exhaustion.
- **Idle with credits live**: 08-30, 08-31, 09-06, 09-07 — four days on which
  the pool was not exhausted and nothing ran. This is a larger loss than the
  dark days and it is not a quota problem at all.

Across the 09-04 week: 4.9 d to exhaustion, of which 2 idle, then 2.1 d dark.
**Roughly 4 of 7 days produced nothing.**

### 15.5 Measurement gotcha — transcripts age out at ~29 days

Weeks older than about a month **cannot be re-measured**. Re-running the probe
today over the 08-07 week returns 3,007 Fable requests against the 4,338 this
document recorded on 2026-08-15, because `~/.claude/projects/-src-mxfs` no
longer holds any turn before **2026-08-10** — 08-07, 08-08 and 08-09 are gone,
and so are 08-12 and 08-13. The 08-14 week (4,509) and the 08-21 week (4,250 vs
4,270 recorded) still reproduce, so the method is sound; the data is not
retained.

**Consequence: the numbers in this document are the only record.** For any
week older than ~29 days, quote this file — do not re-derive, and do not treat
a re-derived undercount as a finding. Anything that must survive gets written
here within the month it was measured.

### 15.6 What the next audit must do

1. **Re-measure the allowance.** One week at 5,808 against six at 4,437 ± 4%.
   If the 09-11 week also lands high, the allowance moved and every plan built
   on ~4,430 is wrong by a third.
2. **Attack the idle days, not the dark ones.** Four idle days with credits
   live cost more than the 2.1 dark days did, and cost nothing to fix.
3. **Hold requests/closure and watch it, not req/prod.** 98 is the number that
   matters. Req/prod is now composition-dominated (§15.3) and will mislead.
4. **Split the release gate or accept the arithmetic.** See §16.
5. **Do not change cutoff or effort.** Four eras at 500k/high, no regression,
   and changing them now makes the the batching and delegation rules attribution permanently
   unanswerable. Unchanged from §12.6 item 5.
6. **The off-pool subagent question is answered for now.** 2,419 subagent
   requests (1,827 sonnet, 592 opus) in Era G with no Fable effect. §12.6 item
   6's ceiling has not been hit; keep watching it.

---

### 15.7 Era F+G — the memo written at the time (2026-09-08)

Era F closed + Era G audit (measured 2026-09-08). Full write-up: §§15 and 16.

#### The two closed weeks

| | Era E 08-21 | Era F 08-28 | Era G 09-04 |
|---|---:|---:|---:|
| terminal exhaustion | 08-24 08:38Z | 09-02 19:55Z | 09-09 01:29Z |
| wall | 3.19 d | 5.66 d | 4.90 d |
| fable requests | 4,250 | 5,808 | 4,627 |
| req / productive action | 2.38 | 1.14 | 1.42 |
| Agent calls | 0 | 194 | 230 |
| subagent reqs (off-pool) | 0 | 1,905 | 2,419 |
| ledger found / closed | 28 / 22 | 61 / 30 | 50 / 47 |
| closed:found | 0.79 | 0.49 | 0.94 |
| requests / closure | 193 | 194 | 98 |
| net open-queue change | +6 | +31 | +3 |

98 requests/closure is the best ever recorded. Section 3.2.4's "flat at 600-750 across every configuration" is three eras out of date; the improvement since is 7x. Batching (the batching rule) and delegation (the delegation rule) are the only changes that fit the timeline.

req/prod rising 1.14 -> 1.42 is COMPOSITION, not a regression: Era G ran 27 of 61 sessions below 420k context against 4 of 60 in Era F, and req/prod is monotonic in context size (1.33 at >420k, 1.68 at 175-300k, 3.75 at 100-175k). Watch requests/closure instead; req/prod is now composition-dominated and will mislead.

#### The allowance constant broke once, upward

Seven weeks of fable requests at exhaustion: 4,244 / 4,635 / 4,338 / 4,509 / 4,250 / 5,808 / 4,627. Six of the seven sit at 4,437 +/- 4.0%. The 08-28 week is +31% out of band and the cause is NOT established. Two unproven candidates: the allowance moved, or the account was served past its cap during the fable-5 -> fable-5-1 rename, which straddles exactly that week (58% of its weighted spend on fable-5, 39% on fable-5-1). Plan against ~4,430, not 5,808.

#### Two probe bugs, fixed in 0.75.79

ccloop_quota_probe.py ended a week at the FIRST "out of usage credits" message in it. Both failure modes appeared in the 08-28 week:
- A refusal 35 seconds after the Thursday reset is the PREVIOUS week's refusal still being retried. Taking it as the boundary reported 7 turns for a week that ran 5.66 days. Fix: --boundary-grace-min (default 45).
- An isolated mid-week refusal (08-29 17:37Z, one message, 3,679 requests) was followed by 2,129 more fable requests. It is a shorter-horizon limit, not the weekly cap. Reading it as the cap understated the week 37% and made section 12 project exhaustion at 1.89 d for a week that ran 5.66 d. Fix: --terminal-quiet-min (default 30) - an exhaustion is the cap only if no fable request follows it.

The probe now also counts distinct requestIds per model family, which is what the pool is actually metered in.

ccloop_delegation_audit.py matched --model by EQUALITY against default claude-fable-5. After the rename it printed "no sessions with requests" - a silent zero that reads as "delegation is unmeasurable". Now a prefix match, default claude-fable.

#### TRAP: transcripts age out at ~29 days

Weeks older than about a month CANNOT be re-measured. Re-running the probe on 2026-09-08 over the 08-07 week returns 3,007 fable requests against the 4,338 recorded on 2026-08-15, because ~/.claude/projects/-src-mxfs holds no turn before 2026-08-10 (08-07/08/09 and 08-12/13 are gone). The 08-14 week (4,509) and 08-21 week (4,250 vs 4,270 recorded) still reproduce, so the METHOD is sound and the DATA is not retained. Consequence: this document is the only record for any week older than ~29 days. Quote it; never re-derive, and never report a re-derived undercount as a finding.

#### Why 2-node TCP is not releasable (section 16)

The 2-node TCP functional board is GREEN: criteria.json rows recorded 2026-09-08 19:48-22:59Z show 2/tcp at 27 PASS, 1 FAIL, and the single FAIL is open_defects. cache_coherency, strong_consistency, mmap_coherency, zero_silent_loss, crash_consistency, dirent_durability, fence_during_write, fault_netpartition, soak, ag_strand_repair, sustained_load, kernel_health, fio_perf and fio_perf_vs_xfs all pass.

tests/suite/open_defects.sh fails while ANY record is OPEN, whatever configuration it describes. Classifying the 91 open records by the configuration their own text says is needed to exercise them (keyword heuristic over id/summary/mechanism/evidence/found/next_step/containment):

| bucket | open | critical | high | major | minor | opened >14d ago |
|---|---:|---:|---:|---:|---:|---:|
| CAW_ONLY | 41 | 25 | 13 | 3 | 0 | 28 |
| SCALE_ONLY (4/8/16/31/32 nodes) | 11 | 9 | 1 | 0 | 1 | 8 |
| TCP_2NODE | 24 | 21 | 2 | 1 | 0 | 3 |
| TRANSPORT_AGNOSTIC | 15 | 10 | 4 | 0 | 1 | 6 |
| total | 91 | 65 | 20 | 4 | 2 | 45 |

52 of 91 (57%) name a configuration 2-node TCP cannot run. Of the 45 records older than two weeks, 36 are CAW-only or scale-only and only 3 are TCP/2-node: the aged residue of the queue is almost entirely work that is no longer in scope.

THE CLASSIFICATION IS A HEURISTIC, NOT AN ADJUDICATION, AND DISPOSES OF NOTHING. A record whose text names CAW may still reproduce over TCP. Reach must be established from evidence per record before any record is assigned to a gate, or assigning a gate becomes a quiet relabel, which the zero-defect bar forbids.

Narrowing scope moved discovery, it did not reduce it: the narrowed week found 50 (second-highest on record) and 21 of the 24 open TCP/2-node records were opened inside the last 14 days. The narrowed scope is itself newly explored territory. What narrowing DID buy: closures 30 -> 47, ratio 0.49 -> 0.94, requests/closure 194 -> 98, net growth +31 -> +3.

The open question for the user, which is a scoping decision and not a disposition: one gate (release needs all 91 closed, including 52 the shipping configuration cannot exercise - never reachable at a ratio below 1) or a per-configuration gate (2-node TCP needs the 24 TCP records plus whichever of the 15 transport-agnostic ones are reachable, ~2,350-3,800 requests, and that is a FLOOR because discovery in that scope has not stopped). Splitting the gate closes and relabels nothing; it only records which release each record blocks, which the ledger does not currently say.

#### Days that produced nothing

Two distinct losses. Dark AFTER exhaustion: 1.34 d (08-28 week), 2.10 d (09-04 week), down from 3.5 d in the 08-21 week - the section 12.1 Opus-fallback lever was pulled exactly once, 09-03, for 840 opus turns, and did not repeat after the 09-09 exhaustion. Idle WITH CREDITS LIVE: 08-30, 08-31, 09-06, 09-07 - four days, a larger loss than the dark days and not a quota problem at all. Across the 09-04 week roughly 4 of 7 days produced nothing.

#### Behaviour (run 140e6b67, 34 sessions)

the Read-tool rule compliance is real now: Read tool 1,402 calls (41.2/session) = 69% of file reads, against the 11% baseline that motivated the rule. Orientation ramp median 7 tool calls. Handoff tier absent on all 34 prompts. Most-read files: xfs/xfs_mxfs_dlm.c 267, dlm/dlm.c 218, dlm/v5_mount.c 209.

#### Housekeeping noticed

- tests/criteria/OPEN_DEFECTS.json is now 2,789,366 bytes / 255 records. CLAUDE.md still says ~559KB / 70 records. Never read it whole; use ./defects.sh.
- VERSION reads 0.75.77 while CHANGELOG.md's top entry is 0.75.78 (now 0.75.79). The VERSION file lags the changelog.

## 16. Why narrowing scope to 2-node TCP did not produce a releasable product

Measured 2026-09-08, at 0.75.77.

### 16.1 The functional board at 2-node TCP is green

From `criteria.json`, rows last recorded 2026-09-08 19:48Z – 22:59Z:

**2 nodes / tcp: 27 PASS, 1 FAIL.** The one FAIL is `open_defects`.

Every functional criterion in the narrowed scope passes: `cache_coherency`,
`strong_consistency`, `mmap_coherency`, `zero_silent_loss`, `crash_consistency`,
`dirent_durability`, `fence_during_write`, `fault_netpartition`, `soak`,
`ag_strand_repair`, `sustained_load`, `kernel_health`, `fio_perf` and
`fio_perf_vs_xfs` included. The board is not what is holding the release.

### 16.2 The gate did not narrow when the scope did

`tests/suite/open_defects.sh` fails while **any** ledger record is OPEN,
irrespective of the configuration that record describes. Classifying the 91
open records by the configuration their own text says is needed to exercise
them:

| bucket | open | critical | high | major | minor | opened >14 d ago |
|---|---:|---:|---:|---:|---:|---:|
| CAW_ONLY | 41 | 25 | 13 | 3 | 0 | 28 |
| SCALE_ONLY (4/8/16/31/32 nodes) | 11 | 9 | 1 | 0 | 1 | 8 |
| TCP_2NODE | 24 | 21 | 2 | 1 | 0 | **3** |
| TRANSPORT_AGNOSTIC | 15 | 10 | 4 | 0 | 1 | 6 |
| **total** | **91** | 65 | 20 | 4 | 2 | 45 |

**52 of 91 open records — 57% — name a configuration that 2-node TCP cannot
run.** They are the majority of the gate and none of the scope.

The age split is sharper than the count. Of the 45 records older than two
weeks, **36 are CAW-only or scale-only and only 3 are TCP/2-node.** The aged
residue of the queue is almost entirely work the user has stopped doing.

**This classification is a keyword heuristic over each record's own
`id`/`summary`/`mechanism`/`evidence`/`found`/`next_step`/`containment` text.
It is not an adjudication and it disposes of nothing.** A record whose text
names CAW may still reproduce over TCP; the heuristic only reports that the
record does not say so. Reach must be established from evidence, per record,
before any record is assigned to a gate — otherwise assigning a gate is a
quiet relabel, which the zero-defect bar forbids outright.

### 16.3 The scope was honoured — and in scope, closure finally outran discovery

| quota week | found | closed | ratio | net |
|---|---:|---:|---:|---:|
| 08-07 | 14 | 7 | 0.50 | +7 |
| 08-14 | 32 | 18 | 0.56 | +14 |
| 08-21 | 28 | 22 | 0.79 | +6 |
| 08-28 | 61 | 30 | 0.49 | +31 |
| **09-04 (2-node TCP)** | **50** | **47** | **0.94** | **+3** |

The narrowed week found 50 defects — the second-highest count on record — and
21 of the 24 open TCP/2-node records were opened inside the last 14 days.

**But the 09-04 quota week straddles the directive that narrowed the scope
(2026-09-05), so the whole-week row above mixes 1.5 days of CAW work into it
and understates what the narrowing did.** Segmented at the directive, with
every record classified by the §16.2 heuristic:

| segment | | TCP_2NODE | AGNOSTIC | CAW_ONLY | SCALE_ONLY | total | ratio |
|---|---|---:|---:|---:|---:|---:|---:|
| 08-28 week | found | 13 | 21 | 19 | 8 | 61 | 0.49 |
| (pre-directive) | closed | 0 | 14 | 12 | 4 | 30 | |
| 09-04 wk, before 09-05 | found | 18 | 2 | 5 | 0 | 25 | 0.56 |
| | closed | 6 | 2 | 5 | 1 | 14 | |
| **09-04 wk, from 09-05** | **found** | **25** | 0 | **0** | **0** | **25** | **1.32** |
| | **closed** | **30** | 2 | 0 | 1 | 33 | |

Two things follow, and the first is the answer to "was the scope honoured?"

- **It was, completely.** From 09-05, **every one of the 25 records found was
  TCP/2-node and 32 of the 33 closed were in scope.** Zero CAW-only and zero
  scale-only defects were opened; none were worked. The loop did exactly what
  the narrowed scope asked of it.
- **closed:found in that segment is 1.32 — above break-even for the first
  time in the project's history.** §14's "the ratio has never exceeded 1 in
  any week" remains true of whole weeks and is now false of the narrowed
  scope measured on its own.

Read 1.32 carefully. It is a 4-day segment, not a week, and part of it is
backlog drain: 31 TCP/2-node records had been opened in the 1.5 weeks before
the directive and 30 TCP records closed after it. The steady-state in-scope
discovery rate is therefore **not yet established** — what is established is
that in-scope discovery ran at ~25 per 4 days while in-scope closure ran at
~32 per 4 days, a net of −7 over the segment.

What the narrowing bought, at the whole-week level: closure 30 → 47, ratio
0.49 → 0.94, requests per closure 194 → 98, net queue growth +31 → +3.

### 16.4 The arithmetic of release

At Era G's measured rates — 47 closures/week, 98 requests each, ~4,430
requests/week — the queue is worked at roughly the speed it is filled. Two
statements follow, and only the second is a choice:

- **Under one gate**, release requires closing all 91, including the 52 that
  the shipping configuration cannot exercise. At a sustained ratio below 1
  that never happens, however many weeks run. This is §14's finding, unchanged
  and now measured for a seventh week.
- **Under a per-configuration gate**, release of 2-node TCP requires the 24
  TCP/2-node records plus whichever of the 15 transport-agnostic ones are
  reachable there — call it 24–39 records, ~2,350–3,800 requests, most of one
  week's pool, *if discovery in that scope stops*. It has not stopped, so
  treat that as a floor, not an estimate.

Splitting the gate closes nothing and relabels nothing. Every record stays
OPEN at its current severity with its evidence intact; the only thing added is
an answer to "which release does this block", which the ledger does not
currently record. That is a scoping decision for the user, not a disposition,
and it is the piece of "lower the scope to 2-node TCP" that was never applied.

Until it is applied, the 2-node TCP board cannot read green no matter how well
2-node TCP works, because 52 of the records failing it are about something
else.

### 16.5 The segmented measurement (2026-09-09)

Measured 2026-09-09, §16.3. Corrects a whole-week measurement that pointed the wrong way.

#### The trap

The 09-04 quota week (09-04 04:00Z onward) STRADDLES the 2026-09-05 directive that narrowed scope to 2-node TCP. Reporting that week as one number mixes 1.5 days of CAW work into it and understates the narrowing badly. The whole-week row reads found 50 / closed 47 / ratio 0.94, which supports "narrowing moved discovery but did not reduce it". Segmenting at the directive shows the opposite.

Any week containing a scope or configuration change must be segmented at the change before its ledger ratio is quoted. A quota week is not automatically the right unit.

#### The segmented measurement

Records classified by the configuration their own text says is needed to exercise them (keyword heuristic over id/summary/mechanism/evidence/found/next_step/containment; priority CAW_ONLY -> SCALE_ONLY -> TCP_2NODE -> AGNOSTIC).

| segment | | TCP_2NODE | AGNOSTIC | CAW_ONLY | SCALE_ONLY | total | ratio |
|---|---|---:|---:|---:|---:|---:|---:|
| 08-28 week (pre-directive) | found | 13 | 21 | 19 | 8 | 61 | 0.49 |
| | closed | 0 | 14 | 12 | 4 | 30 | |
| 09-04 wk, before 09-05 | found | 18 | 2 | 5 | 0 | 25 | 0.56 |
| | closed | 6 | 2 | 5 | 1 | 14 | |
| 09-04 wk, from 09-05 | found | 25 | 0 | 0 | 0 | 25 | 1.32 |
| | closed | 30 | 2 | 0 | 1 | 33 | |

#### What it establishes

- THE SCOPE WAS HONOURED COMPLETELY. From 09-05, every one of the 25 records found was TCP/2-node and 32 of the 33 closed were in scope. Zero CAW-only and zero scale-only defects were opened, and none were worked. The loop did what the narrowed scope asked.
- closed:found = 1.32 in that segment — ABOVE BREAK-EVEN FOR THE FIRST TIME IN THE PROJECT'S HISTORY. Section 14's "the ratio has never exceeded 1 in any week" stays true of whole weeks and is now false of the narrowed scope measured on its own.

#### What it does NOT establish

1.32 is a 4-day segment, not a week, and part of it is backlog drain: 31 TCP/2-node records had been opened in the 1.5 weeks before the directive, and 30 TCP records closed after it. Steady-state in-scope discovery is NOT yet established. What is measured: in-scope discovery ~25 per 4 days, in-scope closure ~32 per 4 days, net -7 over the segment. Two more weeks at fixed scope are needed to say whether the scope is exhausting or holding at ~6 found/day.

#### Why the board still reads FAIL

Unchanged from section 16.2: 52 of the 91 open records are CAW-only (41) or scale-only (11) and cannot reach a the zero-defect bar disposition on a 2-node TCP rig — neither FIXED AND VERIFIED (no test exercises the cause) nor DISPROVED. They are frozen, not slow. The work narrowed; the gate did not. The CAW legs are not lost hardware: 4/caw and 32/caw last ran 2026-09-04, 2/caw 09-04, 16/caw and 8/caw 09-02 (8/caw returning 12 BLOCKED rows), so restoring them is a choice with a cost, not an impossibility.
