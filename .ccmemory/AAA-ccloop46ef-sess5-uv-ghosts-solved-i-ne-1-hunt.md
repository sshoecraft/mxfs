---
name: AAA-ccloop46ef-sess5-uv-ghosts-solved-i-ne-1-hunt
description: sess5: uv-ghost chain SOLVED (leafless dirents; P73 heal landed). Remaining: rv i!=1 bmap del (1-2 nodes/run). P75 discriminator in 3FA53AF8. failed…
metadata:
  type: project
---

# sess5 (ccloop 46efd8b6) — state

## SOLVED: the uv "none remain got=16" ghost chain (RULE-4 proven, platter-decoded)
1. Create-wave leaf wars manufacture LEAF-HASH HOLES (P21H at create: whole per-node ranges missing from leaf while data dirents + inodes live).
2. rm of a hole-name: VFS lookup datascan-heals → xfs_remove → removename leaf-lookup ENOENT → whole unlink txn aborts → `rm -f` swallows → file survives fully = leafless ghost (platter decode: uv dir leaf count=0/stale=46 while db2@66983240 carried node15_file15-30 + node17/22/31 tails; dinode at 31398513; envelope sector offset=196688, agblocks=261653; fsb→daddr uses SEGMENTED agno=fsb>>18).
3. Verify: uv-gone lookups pass because dscan gen-gate (i_mxfs_dscan_clean_key) closes after one clean scan; `ls` readdir walks data blocks → counts ghosts → got=16.
4. FIX v0.10.18: mxfs_dir2_leafless_removename (xfs_dir2_leaf.c, decl in xfs_dir2_priv.h) — on removename leaf-ENOENT (leaf + node fmt hooks), scan data blocks for exact-name dirent, expunge data-side (make_free+freescan+log; bests update safely skipped — understate-only), return 0 so unlink completes. P73-LEAFLESS-RM prints. FIRES 3×/run, works.

## SOLVED: datascan corruption storm (v0.10.19)
The datascan + leafless-remove read data blocks with flags=0 → on LEGAL SPARSE holes (shrink) each read raised xfs_corruption_error + mark_sick (!(flags&XFS_DABUF_MAP_HOLE_OK) at xfs_da_btree.c:2899) → EFSCORRUPTED storms → mv wave dies (PROVEN test4 094029Z). FIX: pass XFS_DABUF_MAP_HOLE_OK in both + gate the P14-DABUF-HOLE probe block to !(flags&HOLE_OK) (readdir holes were spamming it; P14 storms were largely benign readdir holes!).

## REMAINING BLOCKER: i!=1 in xfs_bmap_del_extent_real (xfs_bmap.c:5289→now ~5289+60)
- Signature: mv (xfs_rename) → dir-block free → xfs_bmbt_lookup_eq(got from iext) not found in bmbt → EFSCORRUPTED → dirty trans_cancel → node FS shutdown → that node's renames invisible cluster-wide (~54 failed checks/node on 30 nodes + 1280 on the dead node). 1-2 nodes/run.
- Ruled OUT: reload-identical keep (di_changecount==i_version freezes bmbt too — every extent change logs ILOG_CORE); bmbt-child landing-lag at release (P74-BMBT-RELDRAIN added at mxfs_dir_flush_data_blocks_relsafe = fired 0×, kept in tree, harmless).
- P75-BMBT-DEL-MISMATCH discriminator added at the i!=1 site (build 3FA53AF8 v0.10.21): FUA/plain-read the cursor's leaf daddr vs cached buffer → "LUN==cache ⇒ IEXT STALE" vs "LUN!=cache ⇒ STALE CACHED bmbt leaf". AWAIT run 10:xx.

## Other landed this session
- P72 post-read dir-buf revalidation (xfs_da_read_buf, race-free under the read lock; SELFHOLD-STALE tp-recursed arm). Fires ~0-5/run (gens match at post-read — pre-read invalidation by concurrent readers works).
- Killed orphaned sess4 claude (PID 2123531). SCST live device /home/steve/disk.img o_direct=1 wt=0; multipath = 2 iSCSI paths to same SCST fileio dev (single cache domain — transport exonerated).
- P64-N1F1 (+likely P3L) probes are CAPPED (6000/boot) — per-node write attribution unreliable late in runs.
- progression this session: 0/32(uv got=16, 1 check) → 0/32(rv node4, dscan corruption) → 0/32(failed=110, 2 nodes i!=1) → 0/32(failed=54, 1 node i!=1). Steadily narrowing.

## Watchouts
- WINDOW greps to run start (old-run lines pollute kernlogs).
- rm -f masks ENOENT (uv test); ckeq "uv none remain" counts via ls.
- tests/suite/cache_coherency.sh = the criterion body (cv/cwr/rv/uv phases, coord_barrier MQTT).
- Ladder after cc@32 ×2 green: trio → dir_reuse@16/32 → ./run.sh N caw N=1..32 → echo YES > /src/mxfs/.ccloop/runs/46efd8b6-3dd3-477c-b004-14362c80d8e8/criteria-met
