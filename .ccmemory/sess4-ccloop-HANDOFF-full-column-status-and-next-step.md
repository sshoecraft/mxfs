---
name: sess4-ccloop-HANDOFF-full-column-status-and-next-step
description: sess4(ccloop run6614) HANDOFF: criterion NOT met, marker NOT written. Build 0FB8EBA3 (probes only). Columns @force_block=0: 1/tcp 13/16 (tooling), 2/…
metadata:
  type: project
---

## sess4 (run 6614aa96) HANDOFF — criterion NOT met, marker NOT written

### BIG CORRECTION vs sess3 handoff
sess3 pushed `MXFS_EXTRA_MODARGS='dir_force_block=0'` as the way to run. That is HALF-right: force_block=0 is REQUIRED (cache_coherency needs it) but sess3 didn't realize the tree DEFAULT is force_block=1 (sess67), which DETERMINISTICALLY breaks cache_coherency at 2 AND 4 nodes. **Always run force_block=0** (or flip the compiled default 1→0 at xfs/xfs_mxfs_dlm.c:6607 — evidence supports it, but it leaves dir_reuse 4/8 flaky, so verify first).

### COLUMN STATUS @ force_block=0 (build 0FB8EBA3, probes only, no behavior change)
- **1/tcp = 13/16.** FAIL: online_resize (resize_mxfs tool), dkms_install (88MB stale dumps in tests/tcp/loss_cap2/ from Jun26 — the known breaker, NOT cleaned this session), fault_io_error 0/1. All single-node tooling/fault, orthogonal to DLM.
- **2/tcp = 17/17 ✓ GREEN** (recovers sess58). Full suite, all tests.
- **4/tcp = 14/17.** FAIL: dir_reuse_coherency (flaky ~25-50% at 4 nodes) + fault_netpartition + tcp_dlm_scaling (both CASCADE from dir_reuse's shutdown). Fix dir_reuse → likely 17/17.
- **8/tcp = unrun** (expect dir_reuse + tds-makespan, historical 16/17).

### THE ONE BLOCKER = corrupt dir extent map (cross-node sf→block conversion)
See [[sess4-ccloop-UNIFIED-bug-corrupt-dir-extent-map-both-tests-same-root]]. A dir inode's block0 extent maps to a WRONG physical block (another live dir's block → owner-mismatch struct-fail; or a metadata/garbage block at low daddr 112/120=blk14-15 → CRC-fail). Reader is EX-held, self-created, NOT stale/reused-flagged. Triggered by force_block=1 in cache_coherency and by heavy churn (sf→block) in dir_reuse@fb0 — SAME bug. REFUTED: dir_release_invalidate/dir_relinval_clean OFF does not fix it (bug is at ALLOCATION, not release).

### SHARP NEXT STEP (RULE 4)
Instrument the dir-grow block allocation: xfs_dir2_sf_to_block → xfs_dir2_grow_inode → xfs_bmapi_write / xfs_bmap_btalloc. Log the allocated fsb→daddr + AG-acquire kind (fresh/cached, xfs_alloc.c:3971/4756 mxfs_ag_dlm_lock) at the moment block0 is allocated; read-back the block and check for a foreign/garbage dir3 magic BEFORE inserting the extent. That pins whether it's (a) allocator handing out a live/metadata block (bnobt double-alloc, owner-side drain-before-unlock gap for TCP) vs (b) extent-map insertion corruption. Then fix at the proven site. FAST repro: `./run.sh 2 tcp cache_coherency` at DEFAULT force_block=1 (mostly fails ~34s) OR `scripts/drc_reliability.sh 4 5 dir_force_block=0`.

### TOOLING (harnesses in tree, RULE 3): scripts/ccloop_reset.sh <N>, scripts/drc_reliability.sh <N> <RUNS> [modargs].
### Probes in build 0FB8EBA3 (harmless): P-DIFREE-DBL/CORRUPT (xfs_ialloc.c), P-BLKRV-CRC/STRUCT + P-BLKLK (xfs_dir2_block.c).
See [[sess4-ccloop-MILESTONE-2tcp-17of17-at-forceblock0-config-decision]] [[sess4-ccloop-KEY-bare-defaults-beat-force_block0-dir_reuse-3of3]]
