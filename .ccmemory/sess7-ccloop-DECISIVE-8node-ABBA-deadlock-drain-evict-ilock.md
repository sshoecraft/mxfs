---
name: sess7-ccloop-DECISIVE-8node-ABBA-deadlock-drain-evict-ilock
description: sess7(run6614) DECISIVE: 8/tcp dir_reuse mass-fail (readdir 700/800) ROOT = ABBA deadlock in mxfs_dir_drain_evict_data_blocks blocking down_read(i_lo…
metadata:
  type: project
---

## sess7 (run 6614) — 8/tcp dir_reuse ROOT FOUND + FIXED (build 638E582919B7D49E, testing)

### DECISIVE reframe (fresh N=8 baseline D7A9A25E measurement, drc_reliability 8 3):
The dominant 8-node failure is NOT the scattered ~1-3 dirent loss sess6 chased. It is a **hard node HANG**:
- One node (e.g. test8) wedges: `dd` D-state **368s+**, `ls /mnt/shared/...` hangs. NO shutdown, NO corruption.
- Stack: `xfs_lookup -> mxfs_dlm_dir_consumer_refresh -> xfs_ilock(SHARED,5309) -> mxfs_dlm_ilock_begin -> mxfs_dir_drain_evict_data_blocks -> down_read(&ip->i_lock)` BLOCKED forever.
- Consequence: the wedged node's 100-entry batch (node8_f1..50 + .md5) never publishes -> EVERY peer's readdir = **700/800** (consistent every round) + barrier never completes -> whole test = 0/8. The `node8_f*` names are exactly the lookup_fail entries on test2(9)/test6(54).
- The `imap_to_bp failed rc=-5` face is a RED HERRING: that path (xfs_mxfs_dlm.c:11799) only logs + `i_dlm_stale=false` + returns; it does NOT shut down.

### ROOT (ABBA deadlock, PROVEN by stack):
`mxfs_dir_drain_evict_data_blocks` (xfs_mxfs_dlm.c:7856) took a **blocking** `down_read(&ip->i_lock)` to snapshot the dir extent map. But it runs INSIDE `mxfs_dlm_ilock_begin` (per-inode DLM acquire, serialized). Under 8-node contention a concurrent writer (xfs_create/remove on the same shared dir) holds `i_lock`(WRITE) while waiting for that same DLM grant. Cycle: acquire needs i_lock(read) ⟂ writer holds i_lock(write) & needs grant ⟂ grant handoff needs this acquire to finish. Deadlock. (4-node passes because contention rarely lines up.)

### FIX (build 638E582919B7D49E5DE5FE1, sess7):
Replaced the blocking `down_read` at 7856 with a **bounded trylock**: 50 × (`down_read_trylock` else `msleep(2)`); on exhaustion `return 1` (= "skipped", the existing loss-safe path also used for BTREE-not-read at 7850). Transient writers release in ms → normal case unaffected; a true ABBA bails in ~100ms as skipped (blocks stay cached, caller does NOT advance evicted_gen → next access retries the evict). Mirrors the ABBA-safe trylock idiom in mxfs_dir_flush_data_blocks_relsafe and the durable_signal:8620 warning.

### Also this session (both REVERTED — do not retry):
- candidate-A (sess6 HEAD, arm gg_refresh on hgg==0 && !self_created): caused the SAME drain_evict hang MUCH more often. REVERTED.
- candidate-B (loosen durable_signal gen>0 gate to publish per-create on peer-reachable dirs): per-create synchronous log_force(SYNC)+bwrite under dir ILOCK_EXCL -> peers' EX acquires time out rc=-110 -> mass shutdown at xfs_mxfs_dlm.c:15570. REVERTED. Durability must be at RELEASE, not per-create.

### NEXT: test 638E5829 at N=8 (drc_reliability 8 4) — expect NO hang, readdir 800/800. Then re-confirm 1/2/4 tcp no regress. If the residual scattered ~1-3 loss reappears once the hang is gone, THAT is the next target (release-side durability / ABA — see [[sess6-ccloop-8node-DECISIVE-not-stalebase-release-durability-gap]] [[sess40-FIX-dirblock-ABA-writeback-skip-build-B9F9326E]]). If all of 1/2/4/8 tcp pass -> WRITE THE MARKER.
Shippable fallback if this regresses: 9AA569A0 (== baseline D7A9A25E behavior, which HANGS at 8 so not truly shippable). See [[sess6-ccloop-HEAD-untested-candidateA-hgg0-refresh]].
