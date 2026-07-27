---
name: sess2-tcp-dlm-scaling-root-and-three-fixes-v01182
description: sess2 PROVEN+FIXED v0.11.82: tcp dlm_scaling collapse = per-op flush chain (epoch clock!) + sync-inactivation eager ifree; 3 fixes; dir_reuse 4/4
metadata:
  type: project
tags: [dlm-scaling, flush-epoch, ifree, incarnation-guard, tcp, ccloop-c7ee71c6]
---

# tcp dlm_scaling pace collapse — ROOT + 3 fixes (v0.11.82, ccloop c7ee71c6 sess2)

## Defect
dlm_scaling FAIL at 8/16/32 tcp (NO_TERMINAL_RECORD / rate-floor), deterministic 4/4, while 16/caw+cawd+cawp passed same build/day. ~10 ops/s/node (needs 33+; floor 50). Uniform 100ms/op-triple.

## RULE-4 chain (all measured)
1. dlm_us=0.25ms (P137-INACT) → DLM transport exonerated.
2. Unlink path = the collapse: creates 3-17ms, unlinks 32ms uniform under 8-way (single-node 9.4ms, native <1ms).
3. ftrace: `do_unlinkat → iput → xfs_fs_destroy_inode → xfs_inactive` — **MXFS runs inactivation SYNCHRONOUSLY multi-node** (xfs_inode_mark_reclaimable; deliberate: AGI-bucket recycle race v0.3.59, journal_info==NULL gate) → P137 eager ifree chain (log_force 9-16ms + bounded drain 7-27ms + blkdev flush 2-7ms) charged to EVERY unlink syscall.
4. Guest flush RTT 0.23ms idle, host fsync 1.04ms idle BUT with concurrent O_DSYNC writers p50=3.4ms p95=6.7+ms (LIO fileio write_back=false on ext4: all target IO serializes through the ext4 journal; SCST rigs no-op flushes via nv_cache — why caw* passed).
5. Also per-modify: mxfs_dlm_dir_modify_refresh → mxfs_blkdev_flush_epoch (dir_modify_target_flush=1 sess48-combo + dir_force_evict=1 → runs EVERY create/remove/rename).

## The three fixes (v0.11.82, build DBDF4EBE)
1. **flush_epoch tick-without-flush under fua_disable** (xfs_mxfs_dlm.c mxfs_blkdev_flush_epoch): with FUA reads OFF (default sess94) the read-coherence point is the target cache; a completed write is already re-readable → epoch (which certifies "re-read cannot regress") advances without SYNCHRONIZE CACHE. FUA-active keeps real flush. CRITICAL LESSON: first attempt skipped the CALL entirely at the modify site → **the epoch clock froze → P68-EVDECIDE undurable=1 (b_epoch==cur_mep) forever → every refresh-evict skipped → stale-base RMW storm (P13-COLLIDE "placing onto a DIFFERENT durable dirent", P21H-LEAFHOLE, EEXIST)** → dir_reuse@8 FAIL. The flush was the epoch CLOCK, not just platter-pull. Call restored unconditional; helper made cheap.
2. **ifree_eager_durable=0 default** (new param; xfs_inode.c xfs_inactive_ifree): the eager P137 chain dates to v0.2.5 pre-Phase-2-drain_inode_buffers. Cross-node visibility of freed dinodes rides handoff drains (AG Phase-2 + inode BAST release which does log_force@11557 then drain). eager=1 for A/B: restores old behavior (dir_reuse passed but dlm_scaling 81s FAIL even post-epoch-repair).
3. **P34G-FRESHSRC-INCARN-SKIP** (reload FRESHSRC adopt path, xfs_mxfs_dlm.c ~18876): while WE hold the inode's DLM grant, a disk dinode with di_gen != in-core i_generation can only be the not-yet-destaged PAST (freed predecessor of a reused ino, now longer-lived with eager=0) — never adopt. Generalizes P52-FREEDREUSE (mode==0-only). Evidence: dir_reuse r2 reused round-1 dir ino 175 + file ino 190; pre-guard P34D adopted old-gen images → round-1 dirents resurrected (P127-EEXIST-LOSER name=node1_f15 winner_ino=190) + reload livelock (P91-PROTECT/P34D spin). Post: 0/2 → 4/4 PASS (P34G fired 0× in passing runs — window is timing-dependent; guard is insurance + the epoch repair removed the main driver).

## Results on 8/tcp (build DBDF4EBE, all eager=0)
dlm_scaling PASS 35s (was 77-90 DNF); dir_reuse 4/4 PASS ~102-108s; cache_coherency 558/558, zsl 164/164, fairness, posix_multi green.

## Also in this build
P133-REMOVE staged timing (instr-gated, xfs_remove): commit_ms/pdur_ms + durable/self_created/dgen/pfmt. NOTE: dp_durable gate `!self_created || dgen>0` is defeated by the sess24 0→1 arming artifact (private dirs show dgen=2, durable=1 every remove — flush is cheap now so left as-is, but the gate is dead weight).

## Open
- Full matrix must re-run on v0.11.82 (all prior v0.11.81 cells superseded).
- tcp16 stale-dir defect (P-DIRCRC BLOCK-STALE, task#1) still open — re-repro on 82.
- LIO rig lesson: fileio write_back=false does NOT make flushes free (vfs_fsync still ext4-journal-commits); under concurrent load 3-30ms. Loop-direct iblock is WORSE (9.8ms p50). No spare raw device on clyde.
