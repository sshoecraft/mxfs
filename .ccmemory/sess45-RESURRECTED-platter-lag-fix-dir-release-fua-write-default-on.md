---
name: sess45-RESURRECTED-platter-lag-fix-dir-release-fua-write-default-on
description: sess45 (ccloop 4cb2d0a2): RESURRECTED the dropped platter-lag fix. dir_release_fua_write DEFAULTED ON (build 1DD4B2F3). Root=FUA-platter-lag (LIO wri…
metadata:
  type: project
---

## sess45 — resurrected the platter-lag fix that sess44 dropped

### What happened
The most recent session (resume "session 44") chased the epoch/grant_gen "dead
coherency signal" theory and its CLAUDE.md head is ALL epoch. But ~1 day earlier
(memories [[sess36-BREAKTHROUGH-platter-lag-target-flush-PASS]],
[[sess36-HEAD-handoff]], [[sess36-grant-evict-insufficient-loss-is-platter-lag-reread]])
the project had ALREADY found the real root and TWO working fixes — then lost the
thread at a relay.

### THE PROVEN ROOT (~135 sessions): FUA-PLATTER-LAG, not a stale RMW base
Every base-refresh fix (acquire-evict, dir_gen, epoch, grant_gen, grant_evict)
failed because they all reread from the PLATTER, which LAGS the shared LIO target
write-cache where the releaser's just-drained dirent still sits. The release
drain's bio-level blkdev_flush is DROPPED by LIO (CLAUDE.md: "LIO target drops
SCSI FUA bit"; "pwrite-O_SYNC zero not durable on LIO"), so the releaser's dir
blocks never reach the platter before the peer's FUA read pierces to it → peer
RMWs a base missing the releaser's entry → durable single-dirent loss on ALL
nodes. sess44's "whole-AIL push still loses → release durability sufficient" did
NOT refute this — AIL bio-writes AND blkdev_flush both go through the LIO-dropped
bio path; only an EXPLICIT SCSI command (WRITE16+FUA or SYNCHRONIZE CACHE) forces
the platter, exactly like the read-FUA workaround.

### THE FIX (this session)
`xfs/xfs_mxfs_dlm.c:4218` — `int mxfs_dir_release_fua_write = 1;` (was 0).
Consumed at ~2428 in the release-drain: after the synchronous xfs_bwrite of a
released dir block lands (werr==0), re-issue the SAME block as an explicit SCSI
WRITE(16)+FUA (mxfs_pal_scsi_write_fua_bdev) forcing the platter BEFORE the DLM
unlock. Invariant-1 safe (block already durably bwrite'd). Scoped to released
dir blocks only. Build = `1DD4B2F3`.

### EVIDENCE both fixes passed 8/8 (the ONLY clean PASS 8/8 in project history)
- cap_fw.log (2026-06-27 19:21): MA=dir_release_fua_write=1 → run.sh 8 tcp
  dir_reuse_coherency PASS 8/8, 6m52s (within RULE-0 480s test budget).
- cap_tf.log (2026-06-27 18:11): MA=dir_modify_target_flush=1 (reader-side
  SYNCHRONIZE CACHE, xfs_mxfs_dlm.c ~6185) → PASS 8/8. Two independent
  confirmations of the platter-lag root.
Chose writer-side (dir_release_fua_write): once per released block, not per
reader-modify; sess36-HEAD called it "stronger".

### OPEN (validating now): RELIABILITY. Both prior PASSes were single runs.
Running `tests/drc_cap8.sh 3` (8/tcp dir_reuse ×3 clean-reboot) →
scratchpad/validate8_fua.log. NEXT: if 3/3, run FULL `./run.sh 8 tcp` (regression
+ RULE-0 perf check), then 4/2/1 tcp full suites. Criterion = full 1/2/4/8 tcp
100%. dir_modify_target_flush stays default-0 (belt-and-suspenders available).
