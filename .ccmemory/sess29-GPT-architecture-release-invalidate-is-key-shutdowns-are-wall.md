---
name: sess29-GPT-architecture-release-invalidate-is-key-shutdowns-are-wall
description: sess29(ccloop) PIVOTAL: dir_release_invalidate=1 makes dir data+leaf coherent (lookup_fail→0, loss 18→2 per sess19). The WALL is 2 pre-existing shutd…
metadata:
  type: project
---

## sess29 — GPT-5.5 consult + A/B results: the real blocker is the shutdowns, not the dirent loss

### A/B results (8/tcp dir_reuse, build BA856D08, drc_one.sh 0 24, DRC_STREAM)
- **dir_write_merge=1 alone**: early rounds readdir=800 (data loss fixed) but lookup_fail=1 (leaf hole) + occasional +1 over-count. Pre-existing shutdown (test4 DABUF_HOLE) at round 5.
- **baseline (all levers off)**: round-5 readdir=791 (data loss), then xfs_defer 0x8 shutdown round 15 (test7).
- **dir_postread_reread=1**: CATASTROPHIC — all 8 nodes shut down round 1 (FUA leaf re-read TEARS vs target writeback cache). DO NOT USE (matches sess67 revert).
- **dir_release_invalidate=1 + dir_write_merge=1**: rdmiss=1-2, **lookup_fail=0** (leaf now coherent!), but +1 OVER-count at round1 + shutdowns (DABUF_HOLE ×many, xfs_defer ×8). 

### KEY FINDINGS
1. **dir_release_invalidate=1 is THE dir-coherency lever** (GPT's primary fix == sess19's 18→2 result). On EX release it xfs_buf_stale()'s every clean+durable dir DATA/LEAF buffer (after a proven-durable bwrite) so the next acquire cold-reads the coherent LUN image. Covers leaf → lookup_fail→0. **Should likely become default 1.** Default currently 0.
2. **My dir_write_merge causes a +1 OVER-count = a cross-block DUPLICATE**: the chokepoint merge only checks the SINGLE block being written for the name, not the whole multi-block dir, so it grafts a name that already lives in ANOTHER data block → duplicate → readdir 801. To keep the merge it needs whole-dir name dedup (hard at the bio chokepoint) OR drop it in favor of release_invalidate. Merge is net-neutral/negative when release_invalidate is on. KEPT default-off.
3. **THE GATING WALL = 2 pre-existing SHUTDOWNS** (exist with all levers off too):
   - **DABUF_MAP_HOLE_OK** (xfs_da_btree.c:2876): a dir leaf walk maps logical block bno=1..4 → HOLE. release_invalidate fixes leaf CONTENT (lookup_fail→0) but NOT the EXTENT-MAP staleness (the cached i_df extent map references blocks a peer freed/grew). Needs reacquire-time extent-MAP rebuild (sess54 mxfs_dlm_reload_inode / dir_ex_stale_refresh) — distinct from buffer invalidation.
   - **xfs_defer 0x8** (xfs_defer.c:721, SHUTDOWN_CORRUPT_INCORE): xfs_defer_finish_one returns error = AG free-space double-alloc / bnobt-cntbt family (sess38-47). A deferred free/alloc touches bnobt/cntbt after AG EX was dropped.

### GPT-5.5 ARCHITECTURE (RULE-5 consult, the unifying invariant)
> **No old-epoch XFS buffer (dirty/pinned/in-AIL/delwri) covered by a DLM resource may reach disk after that resource is released. If it can't be drained+invalidated, the unlock must NOT complete.** FUA reads are NOT a coherency primitive (they read the platter which LAGS the target writeback cache → tear). Coherency = DLM exclusion + writer blkdev_issue_flush before unlock + local buffer INVALIDATION on release + PLAIN cold-read on reacquire.
- **#2 leaf**: don't FUA-reread, don't byte-merge leaf. Best: drain+flush+INVALIDATE all dir-fork buffers (data+leaf+node+freeindex) at release (no skip path — wait out pin/AIL), plain cold-read on reacquire (== dir_release_invalidate). Repair fallback: rebuild leaf-from-data transactionally under EX (leaf has no names; hash+address from data blocks).
- **#1 data**: chokepoint merge is mitigation only. Robust = reacquire-time TRANSACTIONAL logical re-apply (xfs_dir_createname our missing op) OR (better) eliminate the need by full release-drain+invalidate so no async destage survives unlock.
- **#3 AG**: copy GFS2/OCFS2 rgrp model. Hold AG DLM EX THROUGH xfs_defer_finish() (not just intent-queue); drain AGF/AGFL/bnobt/cntbt/AGI/inobt buffers + flush + invalidate perag allocator state on release; reread AGF+btrees under AG EX on acquire. The xfs_defer_finish_one failure = a deferred alloc/free path escaping AG-EX lifetime.

### NEXT (RULE 4, priority)
1. Test **dir_release_invalidate=1 ALONE** (no merge) to confirm sess19's 18→2 on current build + measure how often the 2 shutdowns gate.
2. Fix **DABUF_HOLE** = reacquire extent-MAP rebuild (check dir_ex_stale_refresh wiring/default; the cached i_df extent map must refresh when a peer grew/freed dir blocks).
3. Fix **xfs_defer/AG double-alloc** = audit AG-EX lifetime vs xfs_defer_finish (GPT #3).
Build BA856D08 (= keeper C1B4BFC0 behaviorally, all new levers default-off). See [[sess29-write-merge-fix-implemented-build-BA856D08]] [[sess19run-PROGRESS-dir-release-levers-cut-lowmht-loss-18to4]] [[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]].
