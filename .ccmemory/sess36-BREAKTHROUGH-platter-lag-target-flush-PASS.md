---
name: sess36-BREAKTHROUGH-platter-lag-target-flush-PASS
description: sess36 BREAKTHROUGH: dir_modify_target_flush=1 (SYNCHRONIZE CACHE before post-evict FUA reread) → drc 8/tcp PASS 8/8 (1 run). Root=FUA reread hits pl…
metadata:
  type: project
---

## sess36 (ccloop 4cb2d0a2) — LIKELY ROOT FOUND after ~135 sessions: FUA-platter-lag.

### THE RESULT: `dir_modify_target_flush=1` → `./run.sh 8 tcp dir_reuse_coherency` = **PASS 8/8** (1 clean-reboot run, ~6min incl reboot). Confirming reliability via 5-run batch (batch_tf.log).

### ROOT (proven mechanism, sess36 dirwr capture + this PASS):
The durable single-dirent loss (readdir=799, e.g. node2_f49 on daddr 14654480) is NOT a stale CACHE base — every cache-base-refresh fix (acquire-evict, dir_gen, epoch, grant_gen, the new grant-evict) FAILED because they all refresh from the wrong SOURCE.  A peer's post-evict **FUA re-read hits the PLATTER, which LAGS the shared LIO target write-cache** where the writer's just-drained dirent still sits (CLAUDE.md: "LIO target drops SCSI FUA bit"; "pwrite-O_SYNC zero not durable on LIO").  So the peer cold-reads an image MISSING the writer's add, RMWs its own files onto it, release-drains the block WITHOUT the peer add → durable loss on ALL nodes.

### THE FIX THAT WORKS: dir_modify_target_flush (xfs/xfs_mxfs_dlm.c ~5487, after the modify-evict): issue SYNCHRONIZE CACHE to the shared target so the writer's drained dirent (parked in target write-cache) reaches the platter BEFORE the post-evict FUA reread → the reread is coherent.

### NEXT (after batch confirms 5/5):
1. If reliable: this DIAGNOSTIC fires SYNCHRONIZE CACHE per-modify (RULE-0 slowness risk; single run ~6min was OK but verify within drc budget 480s). OPTIMIZE to the cheapest correct form: flush at the WRITER's RELEASE-DRAIN (once per EX release, not per reader-modify) so its drained blocks reach platter before unlock → peers' FUA reads are valid. Check dir_release_fua_write / dir_release_flush_all_done / the Invariant-1 blkdev_flush — the release-drain's existing flush evidently does NOT reach the LIO platter; make it a real SYNCHRONIZE CACHE.
2. Then re-run FULL 1/2/4/8 tcp criteria (reboot clean between).
3. grant_evict (this build) is then likely UNNECESSARY (the base was never the problem) — consider reverting to reduce churn, OR keep (harmless).

### Build on disk 64544CAD (grant_evict=1 default, conv_genbump=0). Test with MXFS_EXTRA_MODARGS="dir_modify_target_flush=1". Repro: scratchpad cap.sh / batch.sh. See [[sess36-grant-evict-insufficient-loss-is-platter-lag-reread]] [[sess26-...]] (dir_modify_target_flush was added sess26 as a diagnostic, never confirmed until now).
