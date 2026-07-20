---
name: sess62-PROVEN-ROOT-4way-logical-block0-split-divergent-extent-map
description: sess62 PROVEN ROOT (direct evidence): dir_reuse 4/tcp node1_f1 loss = 4-way logical-block0 SPLIT — each node calls data_init(block0) at a DIFFERENT d…
metadata:
  type: project
---

## sess62 — dir_reuse_coherency 4/tcp PROVEN ROOT (RULE 4, direct kernel evidence)

Criterion: 1/2/4/8 tcp 100%. 1✅ 2✅ (sess58). **4/tcp FAILS only on dir_reuse_coherency**; 8 never run. Build chain this session ended at 83C634AD (probes only, baseline-equivalent behavior).

### THE FAILURE
node1_f1 — the FIRST dirent rank1 creates into the freshly-recreated (reused-inode) shared dir — is DURABLY lost from disk ~EVERY round (17-24/24 rounds fail; all 4 nodes report it gone after drop_caches, LOOKUP_ENOENT). Occasionally +1 more entry. 2/tcp PASSES; only 4-node fails.

### PROVEN ROOT — 4-way logical-block-0 SPLIT (divergent extent maps)
New always-on probe P62-DATAINIT-BLK0 (xfs/libxfs/xfs_dir2_data.c, logs every xfs_dir3_data_init of LOGICAL block 0 of a multinode non-root dir): **EACH of the 4 nodes calls data_init(logical block 0) for the SAME reused dir inode (131) at a DIFFERENT physical daddr**, multiple (2-5) times/incarnation, buf_done=0 (fresh get_buf alloc each time):
  test1 block0@daddr=120 (AG0); test2 @102568048; test3 @18839088/4186520/62796792; test4 @75356136.
(Different AGs = per-node AG allocation affinity; that's a symptom, not the cause.) Write-side probe P62-DWR-N1F1 confirms node1's whole block (incl node1_f1) is written intact to daddr=120 by test1/test2, but verify resolves the dir's logical-block0 to a DIFFERENT daddr (4186520) with ZERO node1 entries → rank1's block0 orphaned.
So the 4 nodes have DIVERGENT in-core data-fork extent maps; each independently materializes logical-block-0 as a new physical block instead of adopting the peer's already-committed block0. Last writer's inode wins; others' block0 (incl node1_f1) orphaned.

### REFUTED this session
- **NOT DLM double-grant**: master-side dg_shadow P-DOUBLEGRANT (2nd EX owner) AND P-STALEMASTER-GRANT (split-brain master) BOTH = 0 across all nodes (live + failure snapshots). EX is serialized.
- **force_block=1 does NOT fix it at 4 nodes** (TESTED): split persists, 4 different block0 daddrs. (sess43 force_block fixed 2/tcp; only affects the creating node's mkdir, peers still independently materialize block0.)
- **NOT shortform-reconversion-only**: P42-SFCONV fires only ~2× in 24 rounds (reused dir treated as already-block via cache-hit P128-REARM-UNPUB), yet split happens.

### GPT-5.5 consult (RULE 5 justified — complete proven diagnosis, multiple refuted fixes, architectural) — VERDICT
Stale in-core data-fork EXTENT MAP, not scalar fmt/size. Two equivalent gaps:
1. EX-acquire reload adopts scalar dinode fields but does NOT destroy+rebuild the i_df extent cache → xfs_bmapi_write trusts stale map (block0=hole/wrong-daddr) → allocates new block0; OR
2. RELEASE side does not PUBLISH the dir's inode fork (extent-map/block0 mapping) durably to the on-disk inode CLUSTER before granting EX away — peers FUA-read the stale cluster (matches code comments P33-FROMDISK-DIRSHRINK "dinode one growth BEHIND, in CIL/log not yet iflushed to inode cluster"). 
FIX (GPT): (B) before releasing EX, force-iflush the dir inode (+dir blocks) to the home cluster so a peer's FUA read sees the committed extent map; (C) on EX grant where epoch/gen advanced, FULLY rebuild i_df (xfs_idestroy_fork+xfs_inode_from_disk / clear extents-loaded + xfs_iread_extents), not just scalars; (D) restrict the FASTEX self-dirty skip to CONTINUOUS-EX-ownership + unchanged write-epoch only. Adopt at DLM EX-acquire path (before XFS takes ILOCK_EXCL), NOT inside sf_to_block/grow_inode (too late, can't reload under ILOCK).

### NEXT (RULE 4)
Verify which gap (B vs C) by probing: at EX slow-path reacquire of the dir, does the reload reach xfs_inode_from_disk (rebuild) or hit a self-skip guard (P52-FREEDREUSE-DIR-SKIP / P116 / P33-FROMDISK-DIRSHRINK)? And does the RELEASE drain iflush the dir inode cluster (so peer FUA sees block0)? Likely B: dir-grow extent-map update is logged-not-iflushed at release → peer reloads stale cluster → re-grows block0. See [[sess-tcp-FIX-entrypoints-inode-flush-fence]] (prior GPT inode-fork-flush-fence design). Probes added this session (KEEP, low-flood, always-on): P62-DATAINIT-BLK0 (xfs_dir2_data.c), P62-DWR-N1F1 (xfs_dir2_data.c write verify), P62-SF2BLK-CALLED (xfs_dir2_block.c); P60-LBMAP gated behind mxfs.instr; test snapshots dmesg at create-done (drc_create_r${round}_rank${R}.dmesg).</body>
