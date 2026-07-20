---
name: AAA-ccloopa864-sess4-wedge2-is-durable-signal-sync-bwrite-hang
description: sess4 REFINE: dir_reuse@32/caw wedge#2 = per-op durable-signal SYNC xfs_bwrite of dir blocks hangs (xfs_buf_iowait, inflight=0). NOT owner_scan-speci…
metadata:
  type: project
---

# sess4 REFINE — wedge#2 (after orphan fix) = per-op durable-signal SYNC bwrite hang

## Context: FIX#1 (mode=NL orphan wall-clock strand escape, build E5F760E6, VERSION 0.10.50) WORKS + is IN TREE — see memory AAA-ccloopa864-sess4-orphan-fix-WORKS-then-AIL-flush-deadlock. It cleared the orphan wedge (r4→r9) but exposed wedge#2.

## WEDGE#2 (RULE-4, A/B PROVEN): the per-op CAW durable-signal's SYNCHRONOUS dir-block xfs_bwrite hangs.
- Default run: rank1 `rm -rf` D-state 302s, stack: xfs_remove → mxfs_dlm_dir_durable_signal → mxfs_dir_flush_data_blocks → **mxfs_dir_data_owner_scan+0x39d → xfs_bwrite → xfs_buf_iowait** (STUCK). Holds dir ino131 EX → 31 peers starve (P-ACQ-STUCK el_ms→119s, hex=holder, wex=0 all want PR verify).
- **A/B `dir_owner_scan=0` (RULE-4 test): hang did NOT go away — it MOVED to `mxfs_dir_bmbt_scan+0x34f → xfs_bwrite → xfs_buf_iowait`** (r2, rank1 rm). So the wedge is NOT owner_scan-specific; BOTH sync-bwrite scans in mxfs_dir_flush_data_blocks hang. Root = the per-op durable flush's synchronous xfs_bwrite of a dir buffer.
- KEY CLUE: at the hang, dm-0/dm-1 **inflight=0** (NO bio in flight) yet stuck in xfs_buf_iowait. So the write bio is either (a) never submitted (xfs_buf_submit bailed — e.g., buffer in _XBF_DELWRI_Q/FLUSHING collision, XFS_ITEM_FLUSHING-in-AIL-forever per CLAUDE.md design tension #1), or (b) submitted but completion lost/misrouted (mxfs PAL bio path bug), or (c) stuck in xfs_buf_wait_unpin (pinned buf, async log force at owner_scan:1134 insufficient, AIL/log worker jammed). Corroborating: ALL mxfs-ino-bast kworkers D-state in xfs_ail_push_upto_sync_b; P91-BAST-PROTECT storming for the inode-cluster buffer blkno=0x1bf30b0 (flags=0x20 XBF_DONE pin=0) of the rm'd inode range — kept "authoritative", never destaged → AIL jam.

## CURRENT EXPERIMENT (running): `MXFS_EXTRA_MODARGS='dirop_durable_caw=0'` (disables the WHOLE per-op CAW durable flush). Log scratchpad/repro_nodur.log, watcher scratchpad/progress_nodur.log. DISCRIMINATOR:
- PASS (24 rounds, fail=0, no wedge) → per-op flush is DISPENSABLE at 32/caw (release-drain coherency suffices; the v0.5.1 publish-only design). Then: re-verify 2/4/8/16/caw with dirop_durable_caw=0 (coherency via readdir/leaf-hash checks); if all pass, flip default. NOTE sess48 RE-INTRODUCED this flush for a 2/tcp coherency gap (deletes not destaged at release) — TCP not in criteria, but must confirm CAW coherency holds at all node counts.
- FAIL on readdir/leaf-hash → flush NEEDED for coherency → must FIX the sync-bwrite hang itself (instrument xfs_buf_submit: is bio submitted? pin? FLUSHING? — distinguish a/b/c above).
- Wedge elsewhere → deeper.

## NEXT-SESSION: if dirop_durable_caw=0 passes → verify all caw node counts with it, flip default (xfs_mxfs_dlm.c:873 mxfs_dirop_durable_caw=1→0) or gate smarter. If it fails → instrument mxfs_dir_flush_data_blocks / xfs_buf_submit to root the inflight=0 iowait hang (add pre-bwrite state probe: daddr, b_flags, pin, bli li_flags incl FLUSHING, _XBF_MXFS_ALLOC_QUEUED). mxfs_dir_data_owner_scan=xfs_mxfs_dlm.c:1042, mxfs_dir_bmbt_scan nearby. Cluster left wedged after each fail — run.sh prep power-cycles.
