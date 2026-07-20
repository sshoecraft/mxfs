---
name: sess37-HEAD-handoff
description: sess37 HEAD: reads coherent; loss=zombie-BLI reflush; all retire/suppress fixes insufficient(~50%) or corrupt. NEXT=delwri-submit release drain (prop…
metadata:
  type: project
---

## sess37 HEAD — read first. CRITERIA NOT MET (1/2/4 tcp pass keeper-equiv; 8/tcp dir_reuse readdir=799 durable dirent loss).

### BUILD on disk = `DFAEAF39` = keeper-equiv at DEFAULT. All sess37 levers default 0: dir_tenure_reflush_skip (REFUTED), dir_release_retire_bli (REFUTED→shutdown), + diagnostic master_self field (only logs under dataclobber>=1). 1/2/4 tcp unaffected. After `make clean` ALWAYS `make tools`.

### ★ BEST CONFIG (~50%, NOT 100%): `dir_grant_evict=1 dir_addname_coherent=1 dir_addname_epoch_refresh=1 dir_addname_platter_guard=2 dir_zombie_retire=1 dir_zombie_push=1` — all SAFE (read-refresh + !DONE-gated BLI retire). Fails ~round 1 OR 24 (~50% of 24-round runs). Read-side stack alone ≈ same.

### DECISIVE DIAGNOSES THIS SESSION (RULE 4):
1. **Reads ARE coherent** — P28-PLATTER 7152 MATCH vs 48 DIFFER (all DIFFER are dirty=our-work). A clean in-core dir block ALWAYS equals the platter. So the loss is NOT a stale RMW base; it is a **zombie-BLI stale DESTAGE** (block correct at addname, reflushed later in a peer-superseded form). [[sess37-REFUTED-release-retire-bli-and-readside-coherent]]
2. The clobber is genuine-EX (real_mode=5), DONE=0 OR DONE=1, in_ail, bdirty=0, bgen=0/current — occurs even on the MASTER node (so NOT a DLM grant error; intra-node zombie reflush). master_self distribution confounded by 7/8-non-master population. [[sess37-DECISIVE-clobber-on-nonmaster-stale-local-dlm-EX]]
3. The release-drain `xfs_bwrite` (mxfs_dir_flush_one_daddr ~line 1957) makes the block DURABLE but does NOT retire its BLI; `release_invalidate`'s `xfs_buf_stale` (line 2046, default on) marks XBF_STALE but ALSO does not remove the BLI from the AIL → the zombie persists → reflushed later = the loss.

### REFUTED THIS SESSION (do NOT retry): dir_release_fua_write (alone+combo→shutdown); dir_tenure_reflush_skip v1 (DABUF_MAP_HOLE from skipping leaf/node) + v2 (readdir=0 catastrophic); **dir_release_retire_bli (manual xfs_buf_item_done after release bwrite → Metadata I/O Error + FS SHUTDOWN all nodes)**. STANDING: write-side DROP/suppress of dir DATA = corruptor (5×); manual BLI retire after bwrite = corruptor.

### ★★ NEXT — the proper mechanism (NOT yet tried), highest priority:
**Convert the release-drain from per-block manual `xfs_bwrite` to the DELWRI-QUEUE + `xfs_buf_delwri_submit` path** (both exist: pal/linux/xfs_buf.c:6021 xfs_buf_delwri_queue, :6185 xfs_buf_delwri_submit). The normal delwri+submit path runs the standard IO-completion that PROPERLY retires the BLI from the AIL (unlike manual xfs_bwrite, which leaves the zombie, and unlike manual xfs_buf_item_done, which corrupts). In mxfs_dir_flush_data_blocks/mxfs_dir_flush_one_daddr: collect the dir blocks needing flush onto a LOCAL delwri list (xfs_buf_delwri_queue), then xfs_buf_delwri_submit(&list) (synchronous: submits+waits, satisfies Inv 1) — the completion retires each BLI → no zombie survives the EX handoff. Keep DATA+leaf+free+node coverage. This is the clean fix the ~50%-ceiling levers approximate but never fully achieve. Test on top of the best config; gate behind a lever for A/B.
ALTERNATIVELY (if delwri-submit also leaves zombies or is infeasible): GPT's full owner-checkpoint (per-dir registry + quiesce + liveness valve).
FIRST verify (cheap): does a NORMAL xfsaild writeback retire the BLI while the manual release xfs_bwrite does not? If so, delwri-submit is the fix. Instrument the BLI in_ail state immediately AFTER xfs_bwrite vs after a delwri submit.

### Harness: scratchpad/{cap.sh,batch.sh} "<MODARGS>" [N=24]. cap≈6-7min. Cluster clean (FS shut down on nodes by last run; next cap reboots clean). Stream logs tests/tcp/drc_cap/stream_rank*.log (overwritten). See [[sess37-REFUTED-release-retire-bli-and-readside-coherent]] [[sess37-DECISIVE-clobber-on-nonmaster-stale-local-dlm-EX]] [[sess37-residual-is-equal-count-content-divergence-xfsaild-leaf]] [[sess26-PIVOTAL-readside-loses-writeside-corrupts-fix-is-release-fence]].
