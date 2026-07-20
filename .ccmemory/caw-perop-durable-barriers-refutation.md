---
name: caw-perop-durable-barriers-refutation
description: RULE-4 PROVEN sess6: CAW per-op durable publish is LOAD-BEARING (dirop_durable_caw=0 lost dirent r17 cluster-wide). CAW=FUA-read/platter coherency. B…
metadata:
  type: project
---

# CAW per-op durable barriers: tested OFF, REFUTED — keep ON (sess6, ccloop 186320ae)

## Context
8/caw dir_reuse_coherency missed the 100*N=800s budget: steady 40s/round × 24 ≈ 1000s
(create 9-16s, verify 4-14s, rm ~21s ≈ 26ms/unlink), all rounds verifying CORRECT until
timeout-kill. Per-op cost anatomy from the run window (rank1 rm phase): ~3.5 dir-block
writes + 2.4 dinode writes + ~5 reads + P11-FLUSH machinery per unlink.

## Hypothesis (architecturally plausible, WRONG)
Per-op barriers (mxfs_dlm_dir_inode_durable / mxfs_dlm_dir_durable_signal, Road-B
CAW-only) are redundant post-v0.6.4/0.6.5 because: (a) caw_wait_for_grant only grants
on slot compatibility — no waiter self-grants past a live EX holder; (b) the
release/demote drain calls __mxfs_dlm_dir_inode_durable UNGATED on every transport
(sess3 a9a03929) + mxfs_dir_flush_data_blocks, so any acquiring peer reads post-drain
state; (c) the loss families were fixed at acquirer-side roots (acq_epoch, P106-BAIL,
tenure-refuse).

## Experiment (build 9C1728FB = 57773CBD + `dirop_durable_caw` knob, default 1)
`MXFS_EXTRA_MODARGS="dirwr=1 dirland=1 dirop_durable_caw=0" run.sh 8 caw dir_reuse_coherency`
- Create wave halved+ (9-16s → 2.7-7.5s early rounds) — barriers ARE the create cost.
- rm phase UNCHANGED ~17.5-23s — rm cost is the IFREE path (per-op log_force + settle +
  bounded targeted AIL drain + flush in xfs_inode.c ~2983, P137), not dir barriers.
- **Round 17: durable dirent loss — node8_f15 missing from readdir on ALL 8 nodes
  (799/800, lookup_fail=0).** The loss family returns ⇒ REFUTED.

## Why (the design truth)
CAW cross-node coherency is **FUA-read based: peers read the PLATTER**. Anything parked
in the SCST write-back cache between release drains is INVISIBLE to a FUA reader even
after a fully correct slot handoff. So per-op platter publish is load-bearing on CAW —
exactly what the Road-B comment (xfs_mxfs_dlm.c ~700, "sess13/48/49 proven") says. On
TCP peers read through the same target cache, so release-drain durability suffices.

## Consequences
1. `dirop_durable_caw` stays DEFAULT 1 (knob kept for A/B only; refutation documented
   at the definition, xfs_mxfs_dlm.c ~724).
2. dir_reuse budget is transport-aware in run.sh: **caw 140*N** (2→280, 4→560, 8→1120),
   tcp keeps 100*N. Floor ×~1.12 headroom; tighten after healthy PASS walls recorded
   (TIMEOUT_BUDGETS.md updated).
3. If 16/32 rungs blow 140*N superlinearly → that's a NEW scaling bug (CAS contention,
   dir-size growth) to RULE-4, not more budget.
4. Possible future pace work (untested): ifree per-op log_force+flush coalescing during
   storms — but the FUA-read model likely makes it load-bearing too; A/B carefully.
