<!-- Cost-audit chronology 08-11→08-24: Era C quota model, closure-throughput metric, Era E 500k keep, closed:found divergence correction, the ledger-date rule landing. -->
# Cost-audit chronology → ledger divergence → the ledger-date rule (2026-08-11 → 08-24)

Four cost/ledger audits across two weeks that converge on one point: the
`OPEN_DEFECTS.json` ledger's missing dates were not housekeeping, they were
hiding whether the project is converging on the zero-defect bar's zero-defect bar. The
gap got flagged repeatedly, produced one confidently wrong finding, and RULE
8 landed the same day as the correction.

## Era C re-audit (2026-08-11) — `docs/cost-audit.md`

`effortLevel` max→high: output/turn fell 20.5% but weighted/turn fell only
0.8% — cache read/write ate the saving, and turn cadence itself dropped
(372→282/h), so the apparent win was the loop getting slower, not cheaper.
Established the normalize-per-turn discipline for every later cost
comparison in this chain.

the Read-tool rule/8-era mechanism gains were real: orientation ramp 14→5 tool calls,
Read share of file reads 8%→42%, handoff present at 96% of session starts
(handoff bodies still 3x oversized vs target, not the binding cost).

Quota model at this point: account-wide across models/projects, weekly
reset, cap ≈642M weighted/4,571M raw, MXFS share of the pool swung
63%→32% week to week — later superseded by the Fable-request-count model
in `docs/cost-audit.md` (folded in
`compiled-request-economics-delegation-and-safeguard-flags`); kept
here only as the state of understanding at the time.

## Closure throughput, same day — `docs/cost-audit.md`

Introduced the metric that actually matters: weighted-tokens-per-CLOSURE,
not per turn. Cutoff halved cost/closure (500k→145k: 56.7M→25.5M);
effort max-vs-high was noise (25.5M vs 26.7M, n=11/n=5) — max buys no less
throughput per unit quota despite costing more per turn, so effort became a
free choice.

Two findings that later prove load-bearing:
- **Spending more will not shrink the ledger.** Era C: closed 5, found 11,
  net +6 open — running the board discovers defects at least as fast as it
  closes them. Ledger shrinks only when closed:found > 1; Era C was 0.45.
- **"Ledger dating is the weak link — fix this."** 62 of 81 records had no
  parseable `found` date, 19 of 47 closures had no `closed` date. Flagged
  as the cheapest high-value fix available, 13 days before it actually
  landed.

## Era E re-audit (2026-08-24) — `docs/cost-audit.md`

500k cutoff kept (raised 08-21 against the prior week's advice — nothing
regressed): 68% fewer sessions, req/productive-action 2.69→2.38 (−11.5%),
req/closure 751→213 (−72%), mechanism traced almost exactly to 78 fewer
session restarts × the ~5-call orientation ramp. `>420k` peak-context
bucket was the *cheapest* (2.26 req/prod), confirming §3.2.3's direction
even under a deliberately huge-context week.

Caveats attached up front, correctly: don't quote 3.5× bare (campaign-
normalized it's ~2×, Era E's 21 rows ≈ 5-6 campaigns vs Era D's 6 rows ≈ 3
campaigns); Era E was a closure-harvest phase (0 defects found in-window
by the `found`-field date query — this number turns out to be wrong, see
next); not a single-variable change (the batching and delegation rules landed across the same
boundary). Standing recommendation at this point: 500k / high / RULES
9-10 / Opus if it has capacity.

## The correction (same day) — `docs/cost-audit.md`

User pushback: throughput isn't the goal, closing the ledger is. Re-measured
on that basis and the throughput story doesn't survive:

- Open queue: 28 (08-07) → 34 (08-11) → 44 (08-15) → **56** (08-24, 142
  records, 39 critical — no trivia tail, the whole queue is release-blocking
  under the zero-defect bar).
- closed:found: Era C 0.45 → Era D+E (08-15→08-24) 0.73. Improved 62%,
  **still below 1** — the only threshold that matters. Below 1 the queue
  grows regardless of loop speed; Era E's 3.5x closure gain bought a slower
  divergence, not convergence.
- Config tuning and the Opus lever both fail here: at ~21 closures and ~35
  discoveries/week, doubling the loop doubles both sides and moves the
  ratio nowhere. Convergence requires the discovery rate to fall on its
  own — i.e. the campaign running out of failure space to find, not the
  loop running faster.
- **Reframes the gate**: future weeks are judged on closed:found, never on
  req/closure. req/closure measures spending efficiency; only the ratio
  says whether MXFS is getting closer to shipping.

**The measurement trap that made this correction necessary**: the `found`
field the Era E audit had date-range-queried is not reliably a date field —
only 16 of 142 records carried an ISO date in it (54 held `sessNNN`
strings, 62 were empty). The query silently returned near-zero and produced
a clean, confident, wrong finding: "Era E discovered 0 new defects." The
ledger had actually grown by 45 records that week. This is the direct
trigger for the ledger-date rule, landed the same day.

## the ledger-date rule lands (sess417, 2026-08-24) — `docs/cost-audit.md`

Schema: every record carries `opened` (always), `closed` (iff disposed),
`updated` (always) as bare ISO `YYYY-MM-DD` — a date field holds a date and
nothing else, `2026-08-04 sess80` does not qualify; prose provenance goes
in `found`, which nothing parses as a date. `status` and `severity` also
required, from fixed enums.

Three enforcement layers, all fail-closed (missing validator/python3/
unreadable ledger blocks the write or fails the board, never passes
quietly):
1. `tools/ledger_validate.py` — schema gate, `id: field: reason` on
   failure.
2. `tests/suite/open_defects.sh` — fails the board on a schema violation
   independently of the open count.
3. `tools/hook_ledger_guard.sh` — PostToolUse hook, blocks the write at
   authoring time. Payload arrives as JSON on stdin, not env vars — an
   earlier `$CLAUDE_TOOL_INPUT` version was simply wrong; unparseable
   payload exits 0 (never blocks an unrelated file), a real violation
   exits 2.

Path independence was nearly gotten wrong: first cut hardcoded `/src/mxfs`
in all three and failed *open* on a path miss. Caught by "what if they
clone it to /jimmys_stuff/mxfs?" — a guard that no-ops in a clone is worse
than no guard, because the ledger and the board both look healthy while
the dates rot. Fixed: each tool resolves the repo from its own location
(`readlink -f "$0"` → dirname → `..`), the hook validates the ledger path
out of the tool-call payload, `open_defects.sh` honours `$MXFS_LEDGER`
with `/src/mxfs` only as last-resort fallback. Verified against a real
clone at `/tmp/jimmys_stuff_*/mxfs`.

Backfill (`tools/ledger_backfill_dates.py`, applied 08-24): 280 violations
→ 45. Derives only what a record already states, marks every derived value
in `date_provenance`, writes literal `UNKNOWN` where nothing supports a
date — never invents one, since a wrong date silently corrupts the
closed:found ratio while a missing one announces itself. Also
canonicalized 13 status spellings and moved 85 prose fragments into
`found`. Verified lossless (142 records, 56 open, 86 disposed, no field
dropped). Backup at `tests/criteria/OPEN_DEFECTS.json.backup`.

Top-level ledger structure gotcha: it's a dict `{"_comment": [...], "defects": [...]}`
where `_comment` is itself a list — a "grab the first list" parsing
heuristic gets the wrong one.

Outstanding at landing: 28 records / 36 fields still `UNKNOWN`, board stays
red on schema until hand-filled (mostly old `FIXED AND VERIFIED` records
missing `closed`; five OPEN records missing `opened`, named in the note).

## Standing takeaway

The chain from `docs/cost-audit.md`'s
"fix this" (08-11) to `docs/cost-audit.md`'s
landing (08-24) is 13 days and one wrong headline finding
(`docs/cost-audit.md`).
A metric that fails silently toward good news — the `found`-date query
reporting near-zero instead of "can't compute" — is worse than no metric,
and the fix has to be schema enforcement at write time, not another one-off
audit correction.
