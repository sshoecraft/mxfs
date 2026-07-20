---
name: sess26-DECISIVE-evict-always-evicts-base-is-postevict-stale-read
description: sess26(ccloop): DECISIVE — modify-path evict ALWAYS evicts in-AIL dir blocks (P68 undurable=1 only for done=0 no-op blocks; ZERO undurable=1 in_ail=1…
metadata:
  type: project
---

## sess26 (ccloop 4cb2d0a2) — DECISIVE refutation + new locus

CRITERIA: `./run.sh {1,2,4,8} tcp` 100%. 1/2/4 PASS. 8/tcp lone blocker = dir_reuse_coherency, ~50% flaky (durable lost-update). Keeper build this session = **BD3B026B** (= 5954F53F keeper + INERT default-off `dir_newtenure_evict` lever; functionally keeper, NO regression).

### Refuted this session
- **MHT tuning is a band-aid, NOT a fix**: inode_mht_ms=600 passed 1×; mht=1200 passed 1× (406s) then FAILED run-1 of a passrate batch. Higher MHT reduces handoff race-window FREQUENCY but does NOT eliminate it → never 100%. Dead end.
- **dir_tenure_evict=1**: readdir=0/800 every round (catastrophic). Syncs valid_epoch→master mid-tenure, mis-flags THIS tenure's own earlier blocks stale, evicts un-drained work. DEAD (confirmed sess25).
- **NEW `dir_newtenure_evict` (built, REFUTED, kept default-0)**: detect new tenure = master dir epoch (mxfs_v5_dlm_inode_dir_epoch) advanced past per-inode `i_dlm_dir_evict_mep`; on first modify of new tenure, drop the in-AIL-undestaged keep-guard so durable-but-stale in-AIL base is evicted. → **readdir=0/800**. ROOT: clearing XBF_DONE on an in-AIL-UNDESTAGED block corrupts in-core (the keep-guard is LOAD-BEARING for buffer integrity, not merely conservative). Code in xfs_mxfs_dlm.c (param `dir_newtenure_evict`, field `i_dlm_dir_evict_mep` in xfs_inode.h, P26-NEWTENURE-EVICT probe).

### DECISIVE EVIDENCE (always-on P68-EVDECIDE, real keeper loss run, 8/tcp)
Captured a real multi-loss run (round1 node6_f18.md5; round9 node2_f23.md5; round10 **WHOLE BLOCK** node1_f1..f16+ = one dir DATA block of node1 vanished; all LOOKUP_ENOENT + REREAD_MISS = durable). P68-EVDECIDE (modify-path mxfs_dir_evict_data_blocks decision, always-on capped 6000):
- **undurable=0 (EVICTED): 2559**; **undurable=1 (kept): 3441 — but EVERY kept one is `in_ail=0 dirty=0 pin=0 delwri=0 done=0`** = block is NOT a cached DONE image (already evicted/uncached) → no-op keep, sets all_evicted=false harmlessly.
- **ZERO `undurable=1 in_ail=1`** → the evict NEVER keeps an in-AIL cached block. It evicts ALL cached DONE blocks incl. in-AIL.
- **=> REFUTES the "stale base is a kept in-AIL-undestaged block" theory** (sess25's read-side keep-guard hypothesis). The RMW base IS cold-read after eviction.

### NEW LOCUS (next hypothesis, RULE-4)
Evict works → the post-evict COLD-READ of the RMW base serves STALE. Two candidates:
1. **FUA-platter-lag**: peer B drains its dir block to the iSCSI target WRITE CACHE at release (Inv 1 blkdev_flush should destage to platter); A's post-evict FUA read bypasses the write cache and reads the PLATTER which still lags → A's base stale → A free-slot double-allocs → clobber. (sess35 P35C distinguished "parked in SCST write cache" vs "lost"; verify-phase cold reads ARE coherent because they follow a barrier+sync, unlike create-phase reads racing in-flight drains.)
2. Write-side re-dirty: block re-dirtied after the coherent read, then xfsaild destages stale (sess25 said clobber WRITE is in_ail=1 comm=dd/bash AIL-push).

### NEXT EXPERIMENT (designed, not yet run)
Test FUA-platter-lag: add a gated A-side blkdev_issue_flush (SYNCHRONIZE CACHE) right after the modify-path evict loop, forcing the target to destage write-cache→platter before the RMW FUA read. If dir_reuse passes → bug is FUA-platter-lag → real fix = ensure peer's RELEASE drain truly lands on platter (or A reads coherently). If no change → B's release flush already lands; pivot to write-side re-dirty (instrument the addname base block right after read: compare in-core entry-set vs plain-LUN read; log divergence). Probes/levers all in tree. Other 3 "8/tcp fails" are cascade victims (PASS standalone). [[sess25-PROVEN-clobber-is-background-aild-destage-of-stale-incore-dirblock]] [[sess24-PATCH5-fixes-corruption-passes-8of8-once-but-intermittent-reread-wedge-remains]]
