---
name: AAA-ccloop7251-sess6-freed-inode-relflush-root-fix
description: sess6 ROOT FIX 0.11.18 A0C44CD4: inactivation sets MXFS_IF_DLM_RELFLUSH (freed dinode was never destaged under NL -> stale-disk recycle adopt -> corr…
metadata:
  type: project
tags: [ccloop-72513a13, sess6, corruption, inactivation, relflush, fairness, dir-reuse]
---

# sess6 (ccloop 72513a13) — freed-inode RELFLUSH root fix

## The bug (RULE-4 proven, evidence in sess6 transcript)
8-node create+mv+rm churn on ONE shared dir (dlm_fairness shape) shut down
1-2 nodes within 20s: "Corruption detected! Free inode N has blocks
allocated!" -> trans_cancel -> log error 0x2 -> shutdown.

Chain:
1. rm droplink commits; idle demote (dwork/ilock_end CACHED&&bpend arm)
   strips the file inode's EX in the droplink->inactivation gap
   (P70-BP ENTRY state=3, P6ZC-REL-NOANCHOR "no tenure").
2. xfs_inactive acquires CLUSTER EX (routed) — but per-inode i_dlm_mode
   stays NL. truncate+ifree run; every AIL dinode flush hits
   P119-NONEX-FLUSH-SKIP (mode!=EX => discard, mark clean). The ifree-end
   bounded drain then vacuously succeeds; "P9-INSTR ifree DONE flushed" lies.
3. Platter keeps the PRE-FREE dinode (mode=0100644, nx=1).
4. Next local create reallocs the same ino: P-RECYCLE-GATE sees disk!=incore
   and adopts DISK (gen-blind: disk gen 186 beat newer in-core 187),
   resurrecting the freed extent into the fresh inode.
5. Second free cycle -> frankenstein dinode (mode=0 nblocks=1) + double
   extent-free -> EFSCORRUPTED at xfs_iget_cache_hit recycle check.

Fairness fallout decoded: test's `|| break` on EIO made shutdown nodes look
"starved" (10-38/50 rounds); NO_TERMINAL = live nodes' caw_wait extended
forever against shutdown-but-heartbeating holders (P-SHUTDOWN-FENCE refuses
acquires but heartbeat continues). The sess5 all-FAIL A/B matrix was
knob-independent because the corruption was.

## The fix (xfs/xfs_inode.c, 0.11.18, srcver A0C44CD4CD43D560121C2C7)
In xfs_inactive: once the inactivation DLM EX is acquired
(mxfs_inact_dlm_locked — cluster EX via mxfs_iclus_lock for routed inodes,
else per-inode EX), set MXFS_IF_DLM_RELFLUSH (the sanctioned
"current-tenure release flush" bypass that bast_process already uses).
Clear it right after the INACT-EXREL unlock at out:. Effect: the freeing
transactions' flushes actually write; the existing ifree-end
mxfs_ail_drain_inode_sync_bounded + buftarg_wait + blkdev_issue_flush
destages mode=0 BEFORE the release.

## Verification
- Repro churn (tests/fairness_optime.sh shape): pre-fix 2 nodes shutdown,
  round monopoly 9-vs-6332 (sick-cluster artifact); post-fix 0 corruption,
  0 shutdown, balanced 40-182 rounds, ERRS=0 x8 nodes.
- dlm_fairness@8 PASS 10s/30s three times (warm cluster AND in-board).
- FULL 20-row 8/cawd board PASS on one prep (first time any session).

## Open items
- dir_reuse_coherency@8: 145/145 checks green but 501s wall vs 120s manifest
  budget (~21s/round: rm=800x7.2ms unlinks w/ P15-REL-ABORT per unlink,
  verify 5-10s, create 2-7s, inter-round 3.07s rank1 sync/mkdir tail).
  TIMEOUT_BUDGETS.md documents 140*N caw budget (1120s@8) but manifest=120s
  is the enforced bar. This is the P131/P138 perf program.
- P137-IFREE-TIME drain_us=62xxx instances pre-existed the fix (bound=60ms
  mxfs_ifree_drain_ms) — drain-timeout tail re-exposes the P119 skip after
  RELFLUSH clears; watch for rare stale-free if AIL is wedged >60ms.
- P-RECYCLE-GATE remains gen-blind (adopts older disk gen over newer local
  in-core) — second-layer hardening candidate if the class recurs.

## Tools added (RULE 3)
- tests/fairness_optime.sh — 8-node per-op churn latency + probe deltas.
- scripts/caw_slot_sampler.py — O_DIRECT single-slot time series read from
  clyde's SCST backing file (/home/steve/disk.img, lock region 67149824).
