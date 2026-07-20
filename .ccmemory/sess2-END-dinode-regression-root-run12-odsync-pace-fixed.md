---
name: sess2-END-dinode-regression-root-run12-odsync-pace-fixed
description: sess2(a16ec5f2) END: ROOT=durable dinode nx=9->1 REGRESSION mid-create (inode-cluster false-sharing despite partial_iwrite=1) births torn maps. O_DSY…
metadata:
  type: project
---

# sess2 (run a16ec5f2) END — build 7781DCE7 deployed; criteria NOT met, marker NOT written

## THE SHARPEST LEAD (run12, PROVEN by P62 timeline — pick up HERE)
**The durable dinode of the shared dir REGRESSES mid-create-storm.** Run12 r1 (t=66.5): test1 read disk_nx=9/24576 at t=66.58 while test4 read disk_nx=1 at t=66.52; afterwards ALL nodes watched disk_nx re-climb 1→2→3→4→5→6. The allocation lineage forked: final durable map = [off0, off2@AG6, off3@AG8, off4@AG9, off5@AG10, leaf@AG5] — off1 MISSING (its grower's block was in the lost nx>=2 lineage; block2's grower placing at off=2 proves block1 was mapped at its grow time). Cold readers + FIX-B adopt the holey map → xfs_dir2_leaf_addname → XFS_DABUF_MAP_HOLE internal errors ×N → trans_read of a mapped-but-never-written daddr returns prior-run urandom → EFSCORRUPTED SHUTDOWN (run12 t=86, run9 same face).

Mechanism class: **inode-cluster false-sharing** — ino131 (dir) shares its 4KiB cluster (inos 128-159, AG0) with the first ~28 test files; a node holding a STALE ino131 slot in its cached cluster buffer publishes it when flushing a co-resident dirty inode (e.g. atime-dirtied ino132+ on readers, or unlink chains). Defenses that SHOULD stop it:
- `mxfs_submit_partial_iwrite=1` (DEFAULT ON, verified) — pal/linux/xfs_buf.c:1766 `mxfs_submit_partial_inode_write`: skips NL-not-logged slots, FREE slots, and (sess56) NEVER writes a DIR dinode slot not logged this round "regardless of in-core state".
- P20-CLUSTER-INVAL forced cluster re-reads at bast/reload (xfs_mxfs_dlm.c:9259/11806 — NOTE: they force-clear XBF_DONE printing pin state but NOT skipping on pinned).
**So the regression bypassed all of these.** NEXT-SESSION candidates to check, in order:
1. Whole-write fallback paths in mxfs_submit_partial_inode_write returning false: NO_PAG (P28-IWR-BAIL marker), b_map_count!=1, ni>64, XFS_BLI_INODE_ALLOC_BUF (fresh-chunk whole-write! ial-init of chunk 128-159 happens when? mkfs-time only? runtime re-init after all-free?? xfs_ialloc_inode_init on chunk REUSE = ALLOC_BUF = WHOLE-WRITE INCLUDING STALE ino131 SLOT if the chunk gets freed+re-initialized when all its inodes free — THE rm phase frees inos 132-159 every round; if the CHUNK gets freed (xfs_difree_inode_chunk!) and REALLOCATED next round, xfs_ialloc_inode_init re-stamps ALL 64 slots incl ino131's LIVE DIR SLOT?!?! — inode chunks with the DIR still allocated can't be freed (chunk free requires all-free)... but ino131 IS freed between rounds (rm -rf removes the dir!) → chunk 128-159 could go all-free → chunk FREED → next round's mkdir re-allocates chunk → xfs_ialloc_inode_init stamps ALL slots FREE via ordered buffer + logs logically → the INIT overwrites... this is the sess45 case (they force WHOLE-write for it). Whole-write of the INIT image = all slots FREE — if a PEER's dir-create (new ino131) already published its dinode and THEN the initializer's ordered init-buffer write lands late → REGRESSION TO FREE/EMPTY → re-climb!!! CHECK: who allocates the chunk each round vs who creates ino131; ordered-buffer write timing vs the mkdir's dinode publish; P-DBLALLOC-BIRTH 'foreign=1' at t=56 shows chunk churn.)
2. The classification loop's non-dir held-clean slots (written from possibly stale buffer content) — but victim is a DIR slot, guarded... unless d->di_mode in the STALE buffer says mode=0 (FREE-era image) → treated as free → skipped ✓ still safe. Re-verify by reading loop tail (lines 1990-2110).
3. A non-xfs_buf path writing the cluster daddr (log recovery? none. tools? no).
INSTRUMENT next: watch_daddr on the ino131 CLUSTER buffer daddr (compute: agbno of ino chunk 128>>3=16 → fsb 16 → daddr 128? verify via dir_leaf_dump.py dinode addr print: di_addr byte → /512 - envelope = cluster daddr region) → PW-DADDR WRITE stacks catch the regressing writer red-handed (the watch is IN build 7781DCE7 already! param mxfs.watch_daddr, relative-daddr match, stacks on WRITE).

## Environment/pace state (IMPORTANT)
- **LIO backstore now WRITE-THROUGH**: recreated with write_back=false (Mode: O_DSYNC verified) + emulate_write_cache=1 + emulate_fua_write=1. scripts/lio_tcm_setup.sh updated with full rationale. This FIXED the pace regression from sess2's earlier WCE=1-buffered config (run11 measured: create 4.6→7.7s, rm-gap 3.6→8s, verify unchanged → 22s/round flat, 24 rounds ≈ 525s > 480 budget → timeout FAILs even with ZERO correctness events). Run12 on O_DSYNC: whole run (reset+test to shutdown@r1+faces) = 4m03 — pace looks recovered; NOT yet measured over 24 clean rounds.
- Run11 (buffered-WCE, build 7781DCE7): ALL 24 rounds ran, ZERO verify fails, zero shutdowns, zero rm-victims — pure budget timeout. The correctness races are ~50%/run; when they don't fire the test is otherwise green.
- P-PINNED-REREAD detector (in build): 0 hits so far — reads-over-dirty-BLI not happening; NOTE it is BLIND to inode-cluster buffers (inode mods live in ILIs not BLIs).
- drc_failrounds.txt is append-only across runs; check mtime. Faces-grep in drc_reliability.sh reads unwindowed dmesg = stale-noise; ignore.
- Fresh evidence trails per run: /root/drc_fail(verify)_rN_rankK.dmesg snapshots on nodes; live dmesg rotates in minutes.

## Run ledger this session (8/tcp drc, budget 480s)
run8 (A7D256DD, WCE-buffered): 21+ rounds all-PASS, rm-victim node6_f35.md5 r11-r21 (leaf-hash lookup ENOENT mid-rm only; DSCAN heal masks stat), pace 15.8→28s → timeout FAIL.
run9 (65AED359 watch): shutdown r16 urandom-in-dir-block (= dinode-regression face).
run10: r10 verify FAIL 796/800 — 4 names (node3_f44/f47, node7_f13.md5/f6.md5) missing from readdir on ALL 8 incl creators, P-COUNTREGRESS=0 (fits dinode-regression → orphaned block, not RMW clobber).
run11 (7781DCE7): clean 24 rounds, timeout only.
run12 (7781DCE7, O_DSYNC): shutdown r1 = the diagnosed dinode regression.

## Standing plan to criteria
1. Kill the dinode regression (cluster false-sharing/chunk-reinit): instrument watch_daddr=<ino131 cluster daddr> → catch writer → fix at the proven site.
2. Re-examine FIX-B semantics after 1: keep holey-adopt (legit post-rm) — with the publisher fixed, mid-create torn maps should no longer exist; if a residual guard is needed, distinguish create-phase (dir nlink==2 && never-shrunk?) — prefer fixing publish over refusing adopt.
3. rm-victim face (node6_f35.md5-class): revisit after 1 (likely same root — leaf hash present on DISK (verified valid leaf on-disk run9) but missing from the RM node's in-core leaf image built over a regressed/forked lineage).
4. Pace: re-measure 24-round wall on O_DSYNC; expect ~400-440s ✓; else profile.
5. Then: 8/tcp ≥5 consecutive clean → 4/2/1 regression → FULL ./run.sh N tcp suites ×{1,2,4,8} → only then write YES to /src/mxfs/.ccloop/runs/a16ec5f2-e661-430d-b60e-1535d93bf93a/criteria-met.

Links: [[sess2-a16ec5f2-MIDSTATE-fixAB-in-probe-artifacts-corrected]] [[sess1-END-state-4FC99EB9-next-divergent-grow-tear]]
