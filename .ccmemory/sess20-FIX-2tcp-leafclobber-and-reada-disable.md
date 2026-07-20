---
name: sess20-FIX-2tcp-leafclobber-and-reada-disable
description: sess20 FIX (build E0C391F3): 2/tcp crash_consistency leaf-hash/dirent loss fixed by (1) dir-readahead auto-disable on multinode + (2) image-origin le…
metadata:
  type: project
---

## sess20 (ccloop 8ddb16a2) — 2/tcp criterion FIX. Build E0C391F3 (deployed both nodes via run.sh prep).

## ROOT (RULE 4 PROVEN, build 5E54558B detectors): crash_consistency / cc_blockdir_probe durable dir loss = a directory metadata buffer with **b_mxfs_dir_gen=0** (stale image — set by acquire-time mxfs_dir_evict_data_blocks or fresh-init, NEVER re-stamped to the current dir gen) being RMW'd/flushed by xfsaild OVER a coherent on-disk block a peer grew. P-LEAFWRITECLOBBER: `daddr=2097480 buf_cnt=119 disk_cnt=202 bufgen=0 comm=xfsaild`. Legit current-tenure dir writes carry bgen==i_dlm_dir_gen (P16: dgen=270 bgen=270). The stale bgen=0 buffers come from **dir-block READAHEAD** which bypasses the xfs_da_read_buf coherency gen-stamp (GPT Hole B): a speculative read submitted before a peer write, completing after re-acquire, lands stale content marked XBF_DONE that the acquire evict already passed.

## TWO FIXES (both KEEP):
1. **PRIMARY — dir readahead auto-disabled on multinode** (xfs/xfs_mxfs_dlm.c: `mxfs_dir_no_reada` default 0→1). Gate in xfs_da_reada_buf (xfs/libxfs/xfs_da_btree.c) already scoped to `m_mxfs_dlm && !is_single_node && S_ISDIR` so SINGLE-NODE keeps readahead = NO perf regression. Speculative dir readahead on a concurrently-modified shared LUN is a coherency hazard (GFS2/OCFS2 rationale), not a perf win. With it: crash_consistency 3/3 (was reliably 1/2). sess19's "1/2 regression" was contaminated state.
2. **BACKSTOP — image-origin leaf-clobber write-guard** `mxfs_buf_leaf_clobber_skip` (xfs/xfs_mxfs_dlm.c, declared xfs_mxfs_dlm.h, called in pal/linux/xfs_buf.c xfs_buf_submit_bio right after the mxfs.dirskip block; on true → emulate clean ioend, no bio). For a leaf1/leafn write: FAST PATH bgen>=owner-dir i_dlm_dir_gen → normal write (no disk read; legit add OR remove never skipped). Only bgen<dir_gen → plain-bdev-read coherent disk leaf; skip iff valid LEAF magic + same owner + disk_cnt>buf_cnt (genuine superset). Logs P20-LEAFCLOBBER-SKIP (always-on, ratelimited). Excludes fresh-leaf creation + create-on-fresh-base. (In the final runs P20 fired 0× because readahead-off removed the stale-leaf source; the guard remains as defense-in-depth for any residual pinned/in-AIL stale leaf.)

## DETECTORS ADDED (diagnostic, keep): bgen=%u added to P16-DIRBLK-SUBMIT and bufgen to P-LEAFWRITECLOBBER (pal/linux/xfs_buf.c) — the b_mxfs_dir_gen image-origin epoch, the discriminator that cracked this.

## VALIDATION: ./run.sh 2 tcp = **16/16** (build E0C391F3), reproduced across multiple full-suite runs + crash_consistency 3/3 standalone. dirwr=1 HIDES the race (timing); cc_blockdir_probe is the harsh repro (but it adds rm-rf inode/daddr reuse not in the official suite). The CRITERION is ./run.sh 2 tcp (the official 16-test suite); crash_consistency is its concurrent-same-dir-create test and was THE blocker.

## CAUTION for future: the write-guard's emulate-ioend backstop drops a leaf write whose log delta is still committed — fine for drop_caches-based crash_consistency, but a true node-kill+log-replay could replay a stale-base delta. The readahead-off PRIMARY fix avoids the stale base entirely (no RMW on stale), so the backstop should rarely/never engage. [[sess20-PROVEN-bgen0-leaf-clobber-discriminator]] [[sess19-GPT2-dir-index-freshness-barrier-fix-spec]]
