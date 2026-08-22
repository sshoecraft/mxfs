---
name: feedback-sane-timeouts-derive-from-measured-wall-never-pad
description: USER DIRECTIVE (repeated 50+ times, sess378): timeouts MUST be derived from the MEASURED wall, not padded round numbers. Padding is the #1 recurring…
metadata:
  type: feedback
tags: [rule0, timeouts, user-directive, run.sh, board]
---

« USER DIRECTIVE — sess378, said emphatically and, in the user's words, "at
least 50 times" before this. It kept not sticking because it was only ever
written into RULE 0 prose, never into a `feedback` memory that surfaces in
every session's first `memory_list`. It is here now. »

## The complaint, verbatim in substance

> "your timeouts are incredibly stupid. They make everything you do and every
> test you do take at least 10 times longer than it should"

## What I was doing wrong (sess378, the concrete instance)

Running the 32/caw board in chunks, I wrapped each `./run.sh` chunk in an outer
`timeout` of 420s / 500s / 520s, and set the Bash tool's `timeout` parameter
even higher (440000 / 520000 / 540000 ms).

Every one of those numbers was invented. The chunks' real walls were 26s, 75s,
76s. I picked "a number that fits under the 10-minute tool cap" — which is
precisely the failure RULE 0 names by name.

## THE RULE

**A timeout is a derived number with a shown derivation. If you cannot write
the arithmetic, you do not get to type the number.**

1. **`run.sh` ALREADY enforces RULE 0 per-test.** `tests/suite/manifest`
   column 5 is each test's budget, and the harness uses it as that test's hard
   timeout AND flips PASS to FAIL on `elapsed_s > budget_s`. Wrapping it in a
   padded outer `timeout` adds nothing but latency on a hang. The wrapper's
   ONLY job is catching a harness-level (not test-level) hang.
2. **Derive from the MEASURED last-healthy wall, not from the budget.**
   `./showstat.sh <N> <dlm>` prints `elapsed/budget` for every row. Sum the
   ELAPSED column for the tests in the chunk, add 20%, add 10s of ssh dispatch.
   That is the wrapper. Budgets are ceilings that were themselves set with
   slack; summing ceilings and then padding compounds slack twice.
3. **The Bash tool `timeout` parameter = the derived number + ~5s.** Never a
   round number, never "the max", never 10 minutes.
4. **Never widen a timeout because something did not finish.** The slowness IS
   the bug (RULE 0 §5). Kill it, record FAIL, diagnose.
5. **After a healthy PASS, tighten** — record the actual wall in
   `tests/criteria/TIMEOUT_BUDGETS.md` and move the budget toward it.

## Measured reference walls — 32/caw, 0.14.11, 2026-08-20

Use these to derive; refresh them from `./showstat.sh 32 caw` rather than
trusting this list after it ages.

| chunk | tests | budget sum | ACTUAL wall |
|---|---|---|---|
| prep | `run.sh 32 caw prep_cluster` | 300 | **56s** |
| 1a | precond_readiness, fio_perf, fio_perf_vs_xfs | 140 | **26s** |
| 1b | cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss | 210 | **75s** |
| 2 | dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired | 300 | **76s** |

Whole 28-row board, summed last-healthy elapsed: **~690s**. The board is a
~12-minute job, not an hour. Chunk it only because foreground Bash caps at
10 min — and size each chunk from the table above, so a chunk is ~2-4 minutes
of derived wrapper, not 8 minutes of padding.

Slowest single rows (these set the chunk boundaries): crash_consistency 90s
(AT budget — thinnest margin on the board), dir_reuse_coherency 105s,
ag_strand_repair 79s, dirent_durability 65s, soak 32s.

## Why padding is not free

"It exits as soon as the command finishes, so a big timeout costs nothing" is
wrong in the case that matters. When a run WEDGES — which on this rig is the
normal failure mode, not the exotic one — the padded timeout is exactly how
long the session sits doing nothing. Ten padded wrappers across a session is
where the "10x longer" comes from. It also destroys the assertion: a run that
takes 8 minutes under a 10-minute wrapper reads as success when it is a RULE 0
failure.
