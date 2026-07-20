---
name: sess100_lessons
description: sess100 — ROOT of dir cross-visibility is WRITE-SIDE: note_dir_modified bumps peers' gen at commit but the dir block is never destaged to the shared…
metadata:
  type: project
---

# sess100 (ccloop run 29df431e) — dir cross-visibility root is WRITE-SIDE

## DEPLOYED/SOURCE STATE
- Source reverted to ≈baseline (acquire-side experiment disabled with `false &&` at
  xfs_mxfs_dlm.c ~3203). Built `DB19A553` (NOT deployed). Last DEPLOYED on test1-4 is the
  regressed `84EA79C2` (acquire-side conservative loaded_gen → unlink 500s). **Next session:
  build the write-side fix below, deploy, retest.** Baseline known-good = `D6AD04FE` (sess99):
  cross PASS, rename PASS, unlink FAIL 1 survivor, cwr PASS = 3/4.

## CRITERION STATE (cache_coherency, clean reboot, build D6AD04FE/84EA79C2)
- cross_visibility PASS, cross_write_read PASS (mostly; cwr borderline 1/6 once).
- rename_visibility PASS (baseline). unlink_visibility FAIL = the ship blocker.
- unlink failure (CLEAN isolated run): all 120 exist before delete (no create-loss in
  isolation; create-loss only in cumulative full run after cross+rename stress). 1-3
  survivors = a peer-DURABLY-deleted file still visible on ONE node (node1); all other
  nodes incl. owner agree it's gone = pure reader-staleness on node1.
- NOTE: reset4.sh does NOT reboot VMs (only teardown+remount) → contaminated state gives
  141s/37-survivor JUNK results. MUST virsh destroy+start all 4 (LIBVIRT_DEFAULT_URI=
  qemu:///system) then reset4 for a TRUSTWORTHY (fast ~25-35s) result. Did this in sess100.

## ROOT CAUSE (PROVEN + GPT-confirmed) — WRITE-SIDE "publish before notify" bug
On every dir mutation, `mxfs_dlm_note_dir_modified(dir_ino)` is called INSIDE the txn at
commit (xfs/libxfs/xfs_dir2.c:411 createname, 633 removename, 696 replace). It ONLY stages
an evict-ring entry that bumps PEERS' i_dlm_dir_gen. It does NOT write the modified dir
block to the shared LUN. The block is destaged to the shared device ONLY by (a) xfsaild
lazy writeback (seconds later) or (b) the BAST-release durability fence (xfs_bwrite all dir
blocks + blkdev_issue_flush + xfs_buf_stale). In the unlink test ALL 4 nodes cache the same
dir continuously → NO node is ever BAST'd → each node's deletes sit in its own CIL/AIL/WB
cache, NEVER promptly on the shared LUN. Peer gets "dir changed" gen-bump but the changed
block isn't on the medium → refreshing/cold-reading just re-reads the OLD block. **The gen
bump is a publication event but the data was never published.**
- The DURABLE variant `mxfs_dlm_dir_durable_signal(dp)` (log_force SYNC + flush dir data
  blocks via xfs_bwrite + note) EXISTS (xfs_mxfs_dlm.c ~4766) but is NEVER WIRED IN (0
  callers). It was written sess82 for exactly this and forgotten.

## ACQUIRE-SIDE REFRESH = DEAD END (RULE-4, 4 variants this session, all reverted)
Proven the fast-path dir EX/PR re-grant detects stale_base (i_dlm_dir_gen >
i_dlm_dir_loaded_gen) at xfs_mxfs_dlm.c ~3146 (P-DIRFASTEX) but did NO refresh.
- B1 `5D795627` EX-only evict, no barrier: unlink PASS, rename REGRESSED 0→40 (lost own
  renames; cold-read stale missing own work).
- B2 `1B206382` +blkdev_issue_flush barrier before evict (GPT's 1st design): rename self-loss
  fixed 40→14; residual = can't see PEER renames.
- B3 `02B33DC9` +broaden to PR readers: rename PASS, but unlink 3 survivors (reader stale).
- B4 `84EA79C2` +advance loaded_gen only if drain_evict left==0: unlink 24s→**500s** flush
  storm (stale_base never clears on a node's own dirty block → blkdev_issue_flush every read)
  + still 6-10 survivors.
Conclusion: advancing loaded_gen ⇒ serve stale forever; not advancing ⇒ flush storm. Acquire
side CANNOT fix it because there is nothing newer on the medium to read.

## THE FIX (GPT RULE-5, do this next session) — publish-before-notify
INVARIANT: a dir gen bump must not be visible to peers until the modified dir blocks for that
gen are written to the shared device AND flushed.
### Writer (replace in-txn note_dir_modified with POST-COMMIT publish)
In xfs_remove / xfs_create / xfs_rename, AFTER xfs_trans_commit (NOT inside txn — so
log_force is legal), dir ILOCK still held:
  1. xfs_log_force(mp, XFS_LOG_SYNC)  (or log_force_lsn to commit LSN)
  2. xfs_bwrite the modified dir DATA/leaf/freeindex blocks to home location (wait pin first)
  3. blkdev_issue_flush(bdev)
  4. THEN mxfs_dlm_note_dir_modified(dir_ino)  (bump peers' gen)
  5. set dp->i_dlm_dir_loaded_gen = dp->i_dlm_dir_gen (local is now published)
Remove the in-txn note_dir_modified calls at xfs_dir2.c 411/633/696 (move to post-commit).
RENAME = ONE visibility unit: bwrite old-parent + new-parent + child ".." blocks, ONE flush,
THEN bump gen for all affected dirs (never half-publish).
This is ~ wiring in `mxfs_dlm_dir_durable_signal` but at the post-commit sites (it already
does log_force+flush_data_blocks+note; may need blkdev_issue_flush added + multi-dir for
rename).
### Reader / fast-path acquire (SIMPLE — no acquire-side blkdev_issue_flush)
On stale_base (gen > loaded): if local dirty/pinned UNPUBLISHED dir blocks exist, publish
them first (don't skip+advance — that's the B4 bug); then invalidate CLEAN cached blocks
(clear XBF_DONE, the proven non-regressing evict — NOT xfs_buf_stale per sess99); plain
re-read; advance loaded_gen only after a full refresh. The existing slow-path drain_evict +
read-hook already do most of this; the writer-side publish is the missing half.
### Cost
Synchronous log_force+bwrite+flush per dir op was ~10x slow historically (sess43 wall).
GPT: do it synchronously FIRST for a correct baseline, then optimize with a per-dir publish
queue that COALESCES many commits → one log_force → one batch bwrite → one flush → one gen
bump (preserve the invariant: gen bump after blocks on LUN).

## KEY INFRA
- Trustworthy run: `LIBVIRT_DEFAULT_URI=qemu:///system` virsh destroy+start test1-4, then
  `bash tests/reset4.sh 4` (fua_disable=1 default), then single test:
  `MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh --nodes 4
  --phase cluster --test test_unlink_visibility --pass-file /tmp/.mxfs_pass --device /dev/sda
  --mount-point /mnt/shared`. Full criterion: `bash tests/criteria/cache_coherency.sh --nodes 4`.
- drain_evict now returns int (skipped count) — harmless improvement kept; other callers ignore.
Related: [[sess99_lessons]] [[sess96_lessons]] [[sess82_lessons]] [[sess43_lessons]].
