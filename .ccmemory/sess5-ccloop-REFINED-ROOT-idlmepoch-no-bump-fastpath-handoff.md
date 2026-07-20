---
name: sess5-ccloop-REFINED-ROOT-idlmepoch-no-bump-fastpath-handoff
description: sess5(run6614) REFINED ROOT of dir_reuse lost-update: BOTH coherence signals fail on the storm dir's fast-path cached-grant re-adoption — master dir_…
metadata:
  type: project
---

## sess5 (run 6614) — dir_reuse lost-update: REFINED ROOT (why ALL coherence gates fail)

Confirmed on build 9762C6C6 (dir_relepoch_reread=1 A/B): the already-coded relepoch-reread at buffer-USE (xfs_da_btree.c:4041, GPT Step 4, WITH correct undestaged keep-guard) is **INERT — P50-RELEPOCH-REREAD fired 0×** while dir_reuse still failed 2/6.

### Why: BOTH cross-node-handoff signals fail to fire for the storm dir (ino 131):
1. **Master dir_epoch propagation broken**: mxfs_v5_dlm_inode_dir_epoch(131) returns 0/stale (local granted-lock mirror's dir_epoch lags the master's correctly-sent value). Disables prior_tenure/tenure_stale/newtenure gates. [[sess5-ccloop-ROOT-dirreuse-master-epoch-zero-disables-gates]]
2. **Local i_dlm_epoch does NOT bump** on the storm's handoff: relepoch (stamped = i_dlm_epoch at read) is NEVER < i_dlm_epoch at the next read ⇒ relepoch-reread never fires ⇒ the reliable-local-epoch signal ALSO can't detect the handoff.

### Conclusion: the storm dir hands the inode-EX grant to a peer and back via a FAST-PATH cached-grant RE-ADOPTION that (a) skips the acquire-reload (which would unconditionally stale dir blocks), (b) does NOT bump ip->i_dlm_epoch, (c) does NOT refresh the local lock's dir_epoch. So the node RMW's a stale cached base a peer superseded → 100/400 dirents durably clobbered (P29-DATAWRITE CLOBBER=0 confirms stale-READ not stale-write).

### NEXT FIX (precise, for next session): find the inode-EX cached-grant re-adoption / BAST-then-reacquire fast path (analogous to the AG path pag_dlm_cached reclaim at xfs_mxfs_dlm.c:18889 which DOES bump meta_gen + coldread-discard). On re-adopting a cached inode-EX grant that a peer BAST'd/modified under, it MUST: bump ip->i_dlm_epoch (so relepoch-reread fires) AND/OR run mxfs_dlm_reload_inode's dir-block stale AND refresh the local lock's dir_epoch. Then enable mxfs_dir_relepoch_reread=1 (already coded, correct guard) — it will re-read the stale base before the addname RMW. Search: where i_dlm_mode/i_dlm_ex re-adopts a cached grant without going through the full grant/reload; grep the inode BAST + re-acquire path in xfs_mxfs_dlm.c.

### VERIFIED DELIVERABLE UNCHANGED: 2/tcp = 17/17 (build 9762C6C6, salvage fix). See [[sess5-ccloop-HANDOFF-state-fixes-and-next]].
### REFUTED: relepoch-EVICT (3/8, evicts current work), relepoch-REREAD alone (inert, 4/6), broad salvage (2/6), query-max (~4/6), tenure/force_coherent levers.
See [[sess5-ccloop-ROOT-dirreuse-master-epoch-zero-disables-gates]] [[sess5-ccloop-FIX-relepoch-evict-gpt-design]] [[sess5-ccloop-HANDOFF-state-fixes-and-next]]
