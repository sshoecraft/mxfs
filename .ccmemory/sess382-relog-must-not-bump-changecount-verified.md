---
name: sess382-relog-must-not-bump-changecount-verified
description: sess382 VERIFIED 0.19.2: the drain's re-log inflated di_changecount 4->403 from its own repair; suppressing it under i_mxfs_pipe_relog makes the delt…
metadata:
  type: project
tags: [mxfs, changecount, iversion, relog, verified]
---

# sess382 — the release drain's re-log must not advance the logical version

Landed and verified in **0.19.2 sv `CFE42736F91C2B7DA79436E`**.

## The loop

`di_changecount` is MXFS's cross-node freshness stamp — compared by
`P-RELOAD-IDENTICAL`, `P3-REFUSE-OLDER`, `P189-RELOG-BEHIND-DISK` and the epoch
gates — and sess6 deliberately **forced one bump per CORE-logging transaction**
so it is a true modification counter.

But the release drain's own gated re-log (`P146V-UNLANDED`) *is* a CORE-logging
transaction. So every repair attempt bumped it. A re-log storm therefore walks
the in-core version past the platter's **purely from our own repair attempts**,
and the inode then looks strictly AHEAD of home — which is exactly the state
`P34F-RELOAD-SELFAHEAD-SKIP` refuses to adopt over.

**The repair defeats the recovery that would have resolved it.** Same shape as
the `pending_seq` runaway, on the counter that matters more.

## The fix

`xfs_trans_log_inode` suppresses **both** the upstream clean→dirty `i_version`
bump and the MXFS forced per-CORE-transaction bump when `i_mxfs_pipe_relog` is
set. A re-log is a new *publication attempt*, not a new *logical modification*.

Safe by construction: the re-log site logs `XFS_ILOG_CORE` on an otherwise
untouched in-core inode and never calls `xfs_trans_ichgtime`, so the only
mutation it would make to the persisted image **is** this bump;
`i_mxfs_pipe_relog` has exactly one setter. The `XFS_LI_DIRTY` transition still
runs so the re-log is still flushable. Lever: `mxfs.relog_holds_version`.

## Verification — the ruling's own experiment

Paired A/B, ONE build, knob flipped at runtime, identical injected fault,
identical 120 re-logs, reading in-core version out of `P383-HOME-VS-OWED`:

| `relog_holds_version` | iver first → last | `cc_home` |
|---|---|---|
| 0 | 4 → **403** | 3 (frozen) |
| 1 | 4 → **5** | 3 (frozen) |

~400 phantom modifications manufactured by our own repair, versus a delta of
**zero** across 120 re-logs (5 = the two real touches the test performed). That
is GPT's stated falsifier satisfied.

**Scope note:** this does NOT by itself prevent the wedge — both arms above
still wedged, because `reldefer_reload=0` in both to force the storm. It removes
the false SELFAHEAD, not the wedge.

## Why a board A/B was the wrong instrument

`dir_reuse_coherency` at 32/caw gave `P146V-UNLANDED=0` in **both** arms — that
criterion never exercises the drain's re-log, so the knob had nothing to
suppress and the arms were indistinguishable (`P34F` 16 vs 13,
`P-RELOAD-IDENTICAL` 4875 vs 5264 — noise). **The re-log path is rare under
ordinary board workloads; only fault injection drives it hard enough to
measure.** Reach for the injection harness, not a board criterion, when testing
anything on the drain's repair path.

New reusable harness: `tests/knob_ab.sh <nodes> <dlm> <knob> <value>
<probe,probe,...> <criteria...>` — sets a knob fleet-wide with per-node rc
verification, clears rings so counts belong to the arm, runs the criteria, and
prints fleet probe totals.
