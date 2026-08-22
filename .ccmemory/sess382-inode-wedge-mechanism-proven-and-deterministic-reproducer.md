---
name: sess382-inode-wedge-mechanism-proven-and-deterministic-reproducer
description: sess382 PROVEN: P-INODE-WEDGE root chain = flush fence abandons publication without stamping flush_seq; drain's own re-log bumps pending_seq. Determi…
metadata:
  type: project
tags: [mxfs, wedge, obligation, iflush, P32E, rule4]
---

# sess382 — the P-INODE-WEDGE / self-shutdown chain, proven end to end

Build 0.17.5, srcversion `7524419841C233C8B61FA0F`, 32/caw.

## The chain (rig evidence + code, RULE 4)

1. `xfs_iflush` has **11 distinct "safe skip" fences** that abandon the flush with
   `error = 0; goto flush_out;`. **None of them stamps `i_mxfs_pub_flush_seq`.**
   (P119, P17B, P25, P32F, P32D, **P32E**, P67, P65, P14, P32-NXSHRINK, +1.)
2. The publication obligation is `i_mxfs_pub_pending_seq != i_mxfs_pub_durable_seq`.
   `durable` only advances at `xfs_iflush_finish` from `flush_seq`. A fenced flush
   therefore leaves the obligation **permanently open**.
3. The release drain (`mxfs_dlm_bast_process`) sees the open obligation and re-logs
   the "clean-but-unlanded" core — `P146V-UNLANDED`. That calls
   `xfs_trans_log_inode`, which **increments `pending_seq`** (xfs_trans_inode.c:116).
   **The drain's own repair action feeds the counter it is waiting on.**
4. Measured on test31 (0.17.4): `pending` climbed 577 -> 643 in ~5 s while `flush`
   stayed frozen at **4**. 1:1:1 correlation on ino=4748168 —
   `P32E-DIREPOCH-FENCE`=120, `P146V-UNLANDED`=120, `P176-OBLIGATION-OPEN`=120,
   `P228-RELBAR-DEFER`=400.
5. Badness is pinned at 4 (`MXFS_RELCAUSE_OBLIG_OPEN` alone); the episode records
   progress only on a badness **decrease**; the 60 s no-progress bound expires;
   `mxfs_inode_wedge` pins the grant and `xfs_force_shutdown`s the **whole mount**.

## The discriminator (what the ledger asked for)

Why do most of these recover? **The only path that reconciles the ledger is the
adopt in `mxfs_dlm_reload_inode`** (`xfs_mxfs_dlm.c:26401`, `durable = pending`,
with `P177-OBLIGATION-DROPPED-AT-ADOPT` if a committed change is being dropped).
And **`i_dlm_stale` has NO release-path consumer** — only access paths
(`xfs_iget`/lookup `xfs_inode.c:1630-1711`, readdir) honor it.

So recovery depends on an unrelated **local reader touching the inode within the
60 s window**. Inodes that only the release machinery touches wedge. This matches
sess380's note that the wedged inode's only prior mention was a peer BAST 175 s
earlier.

## Deterministic reproducer (was intermittent, now on demand)

`tests/p32e_fence_ab.sh <n> <dlm> <gate> [criteria]`

Two existing runtime knobs, no new code:
- `mxfs.dir_adopt_at_acquire=0` — CONDITION FORCER. Leaves dirs in the
  `valid_epoch=0` "no baseline" precursor state = the fence's precondition.
- `mxfs.dir_epoch_incarn_gate=0|1` — ARM SELECTOR (raw compare vs predicate).

Paired A/B, ONE build, aged fs, `ag_strand_repair`:

| arm | gate | P32E | P146V | P176 | P228 | **WEDGE** | NOMOUNT | wall |
|---|---|---|---|---|---|---|---|---|
| control | 0 | 120 | 153 | 124 | 408 | **1** | **test20** | 117 s |
| fixed   | 1 | 0 | 5 | 0 | 0 | 0 | none | 77 s |

## P32E raw-compare omission — REAL contract violation, but NOT the cause

`xfs_mxfs_dlm.h:231` states both consumers "must go through"
`mxfs_dir_epoch_superseded()`. Two of three did; **the P32E fence the header names
did not** — it even `extern`-declared the predicate at `xfs_inode.c:7851` and then
compared raw. Fixed in 0.17.5 + added a `P32E-RAWDIVERGE` probe.

**DISPROVED as the wedge cause.** Full aged board, stock knobs, 32 nodes:
`P32E-DIREPOCH-FENCE`=14 but `P32E-RAWDIVERGE`=**0**. Since RAWDIVERGE is
`raw && !sup`, zero divergences over 14 firings means predicate and raw compare
agreed on every evaluation — the patch is behaviorally a no-op at that site.
Reason: `P211-EPOCH-REBASE`=81 fired from the **dir2.c operation gate**, which
normalizes `valid_epoch` before `xfs_iflush` ever runs.

Keep the patch (closes a documented hole, zero cost, board green), but do not
credit it with fixing #380.

## The real fix (GPT RULE-5 ruling, sess382)

A fence that abandons a publication must **resolve** the obligation explicitly, not
leave it open. Ruling: do NOT bare-`durable = pending` (launders a lost update);
add a separate `resolved_seq` frontier with an outcome
(DURABLE / SUPERSEDED / REPLAYED / UNRESOLVED_CONFLICT); drive the reload from a
**release-side worker**, never inline at the fence (the drain is a documented ABBA
site that takes folio locks); and an `UNCOPIED` obligation with no subsumption
proof must **still pin/fence** — otherwise the patch converts a visible shutdown
into silent metadata loss.
