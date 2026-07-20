---
name: sess49-8node-shutdown-is-agdoublefree-from-epochadopt-stale-reload
description: sess49(ccloop): 8/tcp dir_reuse FAILS via FS SHUTDOWN (AG free double-free + dir-fork DELAYSTARTBLOCK -2 + P21H-LEAFHOLE), not just dirent loss. 4-no…
metadata:
  type: project
---

## sess49 (ccloop 4cb2d0a2) — the 8/tcp failure is a SHUTDOWN, worse than the handoff said

### Build EE427F03 = E871702B (prev-session keeper) + my READ-ONLY P49-STALEBASE detector
(detector in xfs_dir2_data_log_entry: walks plain-read backing vs in-core, logs missing peer dirents; reuses existing P13 plain-read, no new I/O, cannot affect correctness).

### MEASURED (fresh runs, drc_dirtyskip.sh):
- **1/2/4-node tcp dir_reuse_coherency: PASS** (4-node 4/4, 12 rounds). Build is NOT broadly broken.
- **8-node tcp: FAIL 0/8 — FS SHUTDOWN**, not the "~1-2/24 dirent loss, no shutdown" the prev handoff claimed. Nodes shut down early (test5 @219s ≈ round 10, test8 @375s). readdir=0/800 for later rounds = the FS is DEAD, not a coherency residual.

### The shutdown signature (test5 dmesg, earliest):
```
xfs_dabuf_map: bno 2 inode 131
[00] br_startoff 2 br_startblock -2 br_blockcount 1   <- DELAYSTARTBLOCK(-2) in a DIR fork = corruption
P22-DATASCAN-HIT ino=131 name="node5_f1.md5" (leaf-hash hole healed)  <- workaround masks it
XFS Internal error: ltbno + ltlen > bno at xfs_alloc.c:2254, xfs_free_ag_extent  <- AG free DOUBLE-FREE
xfs_defer_finish_noroll ... Shutting down filesystem
```
Counts: P21H(LEAFHOLE)=400 (capped), SHUTDOWN=556..1745/node. P49-STALEBASE=0 (didn't fire — the loss path is the corruption/shutdown, not a durable-platter overwrite). DIRTYSKIP all done=0 (benign, confirms sess48).

### DIAGNOSIS: reused dir inode 131's DATA-FORK extent map gets a DELAYSTARTBLOCK(-2) / hole where the leaf references a real block. dirs NEVER use delayed alloc, so this is mxfs-produced. xfs_dabuf_map can't map it (LEAFHOLE tear) AND the allocator double-frees the AG range (ltbno+ltlen>bno) -> shutdown.

### ROOT HYPOTHESIS (testing): mxfs_dlm_reload_inode (xfs_mxfs_dlm.c:11067) does xfs_idestroy_fork + xfs_inode_from_disk (destroy+rebuild data fork from DISK). The keep-stale guards (11983/12377 `if ((dfr_dirty||dfr_grant_held) && !genuine_handoff)`) BAIL the reload when in-core dirty/EX-held — UNLESS genuine_handoff. genuine_handoff is driven by **mxfs_dir_epoch_adopt=1** (DEFAULT 1, line 5291) when grant_epoch>valid_epoch. Under 8-node create churn the adopt reads a NOT-YET-DESTAGED (stale) disk dinode that LACKS our just-committed dir block -> SHRINKS the in-core fork -> next create re-allocs / frees the overlapping AG range -> double-free. Linked to the release-drain coverage gap (disk not a true superset of our work => adopt loses our blocks).

### TEST IN FLIGHT: `tests/drc_dirtyskip.sh "dir_epoch_adopt=0" 24 8`. If shutdowns vanish -> confirmed; then check dirent-loss rate. Fallback levers: dir_gen_per_handoff=0 (line 5288, DEFAULT 1), dir_modify_extent_adopt (0). epoch_adopt+gen_per_handoff are the sess14/26 "proven 4/tcp config" — but may be the 8-node corruptor.

See [[sess48-FINAL-state-extentmap-staleness-is-next-root]] [[sess48-DECISIVE-loss-is-reader-extentmap-staleness-not-writer]].
</body>
</invoke>
