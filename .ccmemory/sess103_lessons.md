---
name: sess103_lessons
description: sess103 — THREE proven fixes (reg-file reuse-adopt, P102 !in_ail RESTORE, modify-path dir cold-read), all KEEP. unlink_visibility PASSes alone; full…
metadata:
  type: project
---

# sess103 (2026-06-06, ccloop run 29df431e) — head build `C0BB2B4F`

Continues sess102. THREE root-cause fixes landed this session (all KEEP, all proven
via RULE-4 instrumented evidence). cache_coherency still FAIL but materially advanced:
shutdowns largely gone, unlink_visibility PASSES in isolation, full criterion = 2/4.

## FIX A (KEEP, PROVEN): RELOAD-SIZE-DROP-SKIP needs a generation check
`xfs/xfs_mxfs_dlm.c` ~2323 (DLM inode reload). sess39/45 size-drop-skip had NO gen
check → under inode-number REUSE it kept a STALE prior incarnation (peer freed+realloc'd
the number as a fresh di_size=0 file with a fresh di_gen) → we then unlink/inactivate
the ghost → bnobt double-free (xfs_alloc.c:2244) / AGI corruption. FIX: gate skip on
`be32_to_cpu(dip->di_gen) == VFS_I(ip)->i_generation`; gen differs ⇒ adopt peer's
incarnation (fall through). Probe `P103-RELOAD-REUSE-ADOPT`. PROVEN via ino=6291588.

## FIX B (KEEP, PROVEN): RESTORE the P102 `!in_ail` exclusion (REVERTS sess102)
`xfs/xfs_mxfs_dlm.c` ~4242 (mxfs_ag_meta_invalidate_stale discard branch). sess102
removed `!in_ail`; that CONFLATES commit (clears XFS_LI_DIRTY, sets IN_AIL, data still
in-core) vs writeback (pushes to SCST, clears IN_AIL). A committed-not-written-back
buffer is `!dirty && in_ail`; discarding loses this-node-ahead work. PROVEN: P82-ADD
(commits inode onto AGI unlinked bucket) → P102-INVAL-INAIL-DISCARD agno=0 daddr=2 AGI →
P71 head=NULLAGINO → xfs_iunlink_remove_inode line 632 corruption shutdown. FIX: add
`!in_ail` back so in_ail buffers fall to the preserve(else) branch. P71 sig-3 ELIMINATED.

## FIX C (KEEP, PROVEN): MODIFY-path acquire-side dir cold-read
`xfs/xfs_mxfs_dlm.c` new `mxfs_dlm_dir_modify_refresh()` (no-relock sibling of
mxfs_dlm_dir_consumer_refresh; caller holds ILOCK_EXCL) + call in `xfs/xfs_inode.c`
xfs_remove just before the sess82 re-validation / xfs_dir_remove_child. sess97 added
the dir cold-read only to the READ path (xfs_lookup); the MODIFY paths RMW'd the shared
dir block from a STALE cached base across a DLM tenure boundary → removing our own
dirent resurrected a peer's already-deleted dirents = ALL-NODES-AGREE durable
lost-update (proven: all 4 nodes saw the SAME 35 leftover files; remount→EFSCORRUPTED).
FIX = gen-keyed evict of clean cached dir blocks before the RMW so it cold-reads the
peer's durable image. Probe `P103-MODIFY-REFRESH`. RESULT: unlink_visibility PASSES in
ISOLATION (all nodes 0 remaining, MODREFRESH fires). **TODO next: also wire
mxfs_dlm_dir_modify_refresh into xfs_rename and xfs_create (only xfs_remove done).**

## CURRENT STANDING (full cache_coherency criterion, fresh cluster)
passed=2 failed=2: cross_visibility PASS, rename_visibility PASS, **unlink_visibility
FAIL (node1), cross_write_read FAIL (node4)**. unlink_visibility PASSES ALONE but FAILS
in the full cumulative sequence (sess86's known cumulative-fragility: state from earlier
sub-tests). A test1 `xfs_buf.c:1701 xfs_buf_submit Corruption of in-memory data`
shutdown also appeared in the full run — investigate (may be the cumulative trigger).
cross_write_read separately hit `DLM inode lock unrecoverable ino=… rc=-110` (writer
starvation, SESS50-STARVE) in an earlier criterion run.

## METHODOLOGY (critical — cost misreads early in sess103)
- `reset4.sh` re-mkfs+mounts but does NOT reboot → dmesg PERSISTS. ALWAYS `dmesg -C`
  on every node right after reset (and before each run) or stale 'Shutting down' from a
  prior run reads as a false fresh shutdown.
- run_tests.sh does NOT reset between iters; once a node shuts the FS, later runs are
  meaningless. Loop = reset + dmesg-clear per run, OR clear dmesg per run on a live FS.
- P103-FUA-DIVERGE fired 0× ⇒ the inactivation-guard FUA disk read is NOT stale-platter
  (that hypothesis REFUTED). P103-CHUNKFREE: every chunk free was legit (freecount=64).

## NEXT SESSION
1. Wire mxfs_dlm_dir_modify_refresh into xfs_rename + xfs_create (mirror xfs_remove).
2. Re-run full criterion; chase the cumulative unlink_visibility FAIL + the
   xfs_buf.c:1701 buf_submit shutdown (likely a cross-sub-test state carryover).
3. cross_write_read: DLM inode-lock writer-starvation (rc=-110) — SESS50-STARVE residual.
Build C0BB2B4F on all 4 nodes. Probes: P103-RELOAD-REUSE-ADOPT, P103-MODIFY-REFRESH,
P103-CHUNKFREE, P103-FUA-DIVERGE, plus PAL helper mxfs_pal_bdev_read_plain_bdev.
</body>
