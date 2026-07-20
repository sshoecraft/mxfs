---
name: Sess21 MXFS — bnobt is not in pag_bcache at fresh-acquire (KEY FINDING)
description: P22-INSTR walk census proves bnobt/cntbt are NEVER in pag_bcache at invalidate_ag_meta time. Bnobt corruption is therefore disk-level, not cache-level. Three runs of v0.3.53/54 all failed at iter-2 to iter-4 with bnobt LEFT-FAIL.
type: project
originSessionId: caa5978b-279a-4e9f-8d30-2a24edc28eab
---
# Sess21 (2026-05-02) MXFS — diagnostic-driven investigation

**Final state**: v0.3.54 in tree = v0.3.52 + two diagnostics:
1. xfs_inode_util.c:478 — agi-recycle pr_warn at next_agino==agino corruption (sess20 handoff request).
2. xfs_mxfs_dlm.c:invalidate_ag_meta — P22-INSTR walk census (per-acquire counter dump of bufs in pag_bcache by ops type).

## THE BIG FINDING — handoff hypothesis #2 disproven

**bnobt and cntbt are NEVER in pag_bcache at fresh-acquire time.**

P22-INSTR census across 6 ACQ-FRESH events (3 on .186, 2 on .182, plus 1 re-acquire):

| node | agno | total | agf | agi | finobt | bnobt | cntbt | inode |
|------|------|-------|-----|-----|--------|-------|-------|-------|
| .186 | 0    | 4     | 1   | 1   | 1      | **0** | **0** | 1     |
| .186 | 1    | 3     | 1   | 1   | 1      | **0** | **0** | 0     |
| .186 | 1*   | 0     | 0   | 0   | 0      | 0     | 0     | 0     |
| .186 | 2    | 0     | 0   | 0   | 0      | 0     | 0     | 0     |
| .182 | 0    | 1     | 0   | 0   | 0      | **0** | **0** | 1     |
| .182 | 1    | 0     | 0   | 0   | 0      | 0     | 0     | 0     |

(* = re-acquire after prior release)

The handoff's hypothesis "invalidate_ag_meta misses bnobt blocks despite walking pag_bcache" was wrong direction. invalidate_ag_meta isn't *missing* bnobt — bnobt isn't in pag_bcache at all when invalidate runs. Either:
- Bnobt buf was evicted between use and walk
- Bnobt buf hold count dropped to 0, rhashtable_remove fired

Either way, the next bnobt access creates a new buf via xfs_buf_read → fresh from disk. **Therefore the bnobt corruption is a DISK-level race, not in-memory cache staleness.**

## Failure distribution at v0.3.54 (= v0.3.52 + diagnostics, no behavioral change)

3 stress runs at v0.3.53, 1 at v0.3.54:
- v0.3.53 run 1: iter-2 bnobt LEFT-FAIL (T1 freeing 5360 blks, ltbno=20472 ltlen=241662)
- v0.3.53 run 2: iter-4 bnobt LEFT-FAIL (T2 side this time)
- v0.3.53 run 3: iter-2 bnobt LEFT-FAIL (T1)
- v0.3.54 run 1: iter-4 bnobt LEFT-FAIL (T1 freeing 29936 blks, agno=0)

100% bnobt LEFT-FAIL across 4 runs of v0.3.53/54. AGI recycle race never surfaces — bnobt fails first.

## Key timing facts

- v0.3.54 run 1 .186 stats end: `ag: acq=4 nest=250 rel=1` (4 acquires, 250 nested cached fast-paths, 1 release).
- The 1 release was REL-INLINE (immediate via Phase 3 `meta_pending==0` path), NOT REL-DEFERRED (iodone-driven).
- Therefore corruption happens **even on the REL-INLINE path**, where Phase 1 + Phase 2 both do blkdev_issue_flush.

## Architectural analysis

bast_work_fn release path (mxfs_dlm_ag_bast_work_fn @ xfs_mxfs_dlm.c:1713):
- Phase 1 (cached=true still): log_force(SYNC) + ail_push_all_sync + blkdev_issue_flush
- Phase 2 (sets demoting=true): log_force(SYNC) + drain_meta_buffers + blkdev_issue_flush
- Phase 3: if meta_pending > 0, defer to iodone. Else REL-INLINE with mxfs_v5_dlm_ag_unlock.

drain_meta_buffers (line 1352) filter: needs `bp->b_log_item` with bli `XFS_LI_IN_AIL`. Skips bufs without bli (i.e., already-flushed bufs whose bli was detached). xfs_bwrite synchronous wait.

iodone path (mxfs_dlm_ag_meta_iodone @ line 2233): NO blkdev_flush (v0.3.26 attempted, deadlocks xfs-buf workqueue, reverted).

## Suspected disk-level race

After Phase 1 + Phase 2 + Phase 3 REL-INLINE, all our local tracked bnobt writes should be on disk durable (blkdev_flush ran twice). Yet bnobt corruption still happens.

Possibilities:
- (a) blkdev_issue_flush is a no-op on this storage stack (LIO/qemu host-cache). State.md sess14/16 document this hypothesis as repeatedly suspected but not directly verified.
- (b) A buf write was submitted by xfsaild AFTER Phase 2's blkdev_flush, before unlock. xfsaild runs asynchronously; demoting=true blocks new TRANS but not xfsaild's submission of pre-existing-CIL items.
- (c) drain_meta_buffers' filter misses bnobt bufs whose bli was detached but write hadn't completed yet (race window between iodone-removes-bli and write-truly-durable).
- (d) The bnobt corruption isn't from peer's stale write at all — it's from peer ALLOCATING a block T1 already owns, then both nodes record different ownership in their inode trees.

## Next-session strategy

1. **Verify (a) host-cache hypothesis**: instrument blkdev_issue_flush with timing/return code logs OR replace with explicit bdev_fsync(REQ_PREFLUSH|REQ_FUA) write. If LIO doesn't honor flush, this would explain everything.

2. **If (b) is real**: hold the AG until xfsaild has no more items for it. Need a way to query xfsaild for AG-specific pending items, or pause xfsaild during demote.

3. **If (c) is real**: extend drain_meta_buffers to wait for in-flight bios on every AG-meta buf (use xfs_buf_iowait under buf trylock, or scan b_state for XBF_BUSY).

4. **If (d) is real**: cross-correlate dmesg from both nodes by realns to verify peer's alloc/free targeted the same block range.

5. The fix candidate "synchronous wait + flush in Phase 3" (eliminating defer-to-iodone) WON'T HELP — current REL-INLINE path already takes that route and corruption still happens.

## Don't-repeat list (cumulative through sess21)

All sess20 entries still valid:
- No xfs_buf_lock on cluster bufs in bast_process (deadlock)
- No xfs_buftarg_wait in bast_process (drain never)
- No blkdev_issue_flush from xfs-buf workqueue context (deadlock)
- No additional pr_warns/waits in bast_process (CAW timeout regression on peer)
- No CAW exponential backoff (dd hangs)
- No xfs_inodegc_flush in AG bast Phase 1 (bnobt regression — re-entrant AG-DLM)
- No Approach A as designed (current->journal_info NULL at iunlock)
- No xfs_log_force_seq with ili_commit_seq (no-op, ili_commit_seq cleared by bast time)

Sess21 NEW: P22-INSTR walk-census diagnostic in invalidate_ag_meta is harmless (no behavioral change), keep through next sessions.

## v0.3.55 attempt — REVERTED hypothesis

bast_work_fn Phase 3: replaced `defer-to-iodone` with bounded inline wait (msleep 1ms loop, 2s deadline) + `blkdev_issue_flush` (safe from system_wq context) + sync `mxfs_v5_dlm_ag_unlock`. Logged "REL-INLINE-V55" to distinguish from old path.

Result: iter-2 bnobt LEFT-FAIL, identical signature family (`bno=131080 ltbno=131080 ltlen=131054 len=65520` — peer freed an extent starting at the same block we're trying to free).

**Critical observation from dmesg**: 
- All 11 ACQ-FRESH events produced REL-INLINE-V55 (not the old REL-INLINE/REL-DEFERRED).
- ZERO "Phase-3 meta_pending timeout after 2s" warnings → meta_pending was always 0 when Phase 3 ran.
- The synchronous wait was a no-op. The added blkdev_flush did not change behavior.

Conclusion: bnobt corruption is NOT from in-flight bio at unlock time. The disk content read by peer's ACQ-FRESH must already be wrong, OR the issue is upstream of release-acquire boundary entirely.

Earlier sess21 claim "bnobt never in pag_bcache" was wrong — one fresh-acquire on agno=1 had bnobt=1 cntbt=1 (got staled). Sometimes bnobt is cached, sometimes not — depends on LRU state.

## v0.3.55 also added to don't-repeat
- Inline-wait + final blkdev_flush in Phase 3: does NOT close bnobt corruption. Don't reintroduce as a fix.

## Sess21 conclusion

Two specific hypotheses ruled out across 6 sess21 stress runs (3 v0.3.53, 1 v0.3.54, 1 v0.3.55):
1. ❌ "invalidate_ag_meta misses bnobt because of skip rules" — bnobt is sometimes in pag_bcache and gets staled correctly, sometimes not in cache at all.
2. ❌ "Phase 3 defer-to-iodone fires unlock before disk durable" — replacing with sync wait+flush+release made no difference.

Remaining unexplored hypotheses:
- (a) Storage layer flush is no-op under load (LIO/qemu host-cache).
- (b) Cross-node alloc race: peer's bnobt-read at fresh-acquire shows blocks free that we already allocated.
- (c) xfs_extent_busy interaction across nodes (busy list isn't cross-node-shared).
- (d) Some non-AG-DLM-protected mutation (rare, would need to find).

## v0.3.56 P23-INSTR + cross-node correlation — REAL BUG FOUND

P23-INSTR alloc-extent diagnostic at xfs_alloc.c:3699 + cross-node dmesg correlation captured a definitive race:
- T2 (.182) at mono 97742.534 P15-INSTR: `claim-empty slot=10369 cas_rc=0` (FUA WRITE durable).
- T1 (.186) at mono 97751.083 P15-INSTR: `find=rc-2 empty_idx=10369` then `claim-empty slot=10369 cas_rc=0`.
- T2's dmesg has NO release event for agno=0 between these two times. **Both nodes briefly held the same EX grant on agno=0.**
- Root cause: `mxfs_pal_bdev_read_prio` (used for read_slot) used bio I/O without FUA. Multi-initiator iSCSI/LIO read cache served T1's read of slot 10369 from a stale snapshot that didn't include T2's prior FUA write.
- Asymmetry: CAW WRITE used SCSI COMPARE AND WRITE CDB 0x89 with FUA bit 0x08 (correct), CAW READ used bio I/O (wrong).

## v0.3.57 fix attempt — BROKEN

Added `REQ_FUA` to bio submission. Result: iSCSI returns -EIO. Kernel block layer doesn't translate FUA on bio reads to SCSI READ FUA on this stack. Stress: iter-1 cascade `DLM inode lock failed rc=-5`.

## v0.3.58 fix — PARTIAL CLOSE

Switched to direct SCSI READ(16) passthrough (CDB 0x88, FUA bit 0x08) via `scsi_execute_cmd`. Mirrors the working CAW WRITE path. Falls back to bio I/O for non-SCSI devices.

3-run distribution:
- run 1: iter-1 `xfs_dir_removename rc=-2 (-ENOENT)` — Mode A family, T2 side. NEVER seen at v0.3.53-57.
- run 2: iter-3 bnobt RIGHT-FAIL (gtbno overlap, different signature from prior LEFT-FAILs).
- run 3: iter-3 bnobt RIGHT-FAIL (similar to run 2).

**Important**: pagf_freeblks now matches agf_freeblks (was diverging by thousands at v0.3.55). The pag-cache-staleness symptom IS closed by FUA reads. But bnobt corruption persists with a new signature variant.

## Sess21 ultimate verdict (revised after run 4)

The CAW disklock READ cache coherency bug was REAL — proven by cross-correlated dmesg evidence of dual-EX-holders. v0.3.58's SCSI READ(16) FUA fix tries to close that bug.

**HOWEVER**: 4-run distribution shows partial close only. Run 4 reproduced bnobt LEFT-FAIL with exact same signature as v0.3.55 (`bno=131080 ltbno=131080 ltlen=131054 len=65520`). And run 4's CAW logs still show dual claim-empty for same slot from both nodes.

**Open question for sess22**: does SCSI READ(16) FUA actually bypass the iSCSI/LIO read cache on this storage? Or is it being silently translated/ignored? The fact that v0.3.58 didn't close the LEFT-FAIL signature suggests it might not be working as intended. Need a directed test (small kernel module: CAW WRITE on one node, SCSI READ FUA on other, verify visibility).

**ALSO**: xfs_buf_read for AG-meta bufs (bnobt/cntbt/etc) still uses plain bio (no FUA). Even if disklock FUA works, AG-meta reads might still see stale storage cache. Sess22 should consider extending FUA to AG-meta reads via either (a) replacing xfs_buf_read for AG-meta with mxfs_scsi_read16_fua, or (b) issuing SYNCHRONIZE CACHE before AG-meta reads on fresh-acquire.

## CRITICAL HYPOTHESIS for sess22 — iSCSI/LIO target may ignore FUA

T2 had ZERO REL-INLINE-V55 events in run 4 dmesg (buffer covers 143657-current). T1 claim-empty slot=30982 cas_rc=0 succeeded — meaning either T2's prior slot data was overwritten back to empty, or T2 never wrote (cas_rc=0 lying), or T1's CAW found "empty" on-disk because target ignored T2's FUA write.

If the iSCSI target isn't honoring FUA, no software fix in MXFS can close this. **Sess22 first action**: verify LIO target config (`emulate_fua_write=1`, qemu disk `cache=none`). If FUA is silently ignored at target, the storage stack itself is the bug.

## Sess21 lessons

1. **REQ_FUA is asymmetric**: SCSI WRITE FUA is supported via bio (block layer translates), but SCSI READ FUA via bio is NOT supported on this iSCSI stack. Use SCSI passthrough for both paths in DLM critical reads.

2. **Cross-node dmesg correlation is essential**: single-node logs missed the dual-EX-holders race. Cross-correlation of P15-INSTR (CAW slot operations) with P10-INSTR (acquire/release) showed both nodes claiming same slot.

3. **Same external symptom can have multiple causes**: bnobt LEFT-FAIL at v0.3.55 was the CAW cache race; bnobt RIGHT-FAIL at v0.3.58 is a different race. Don't assume one fix closes all variants of "ltbno+ltlen > bno"-style errors.

4. **CAW slot wall-clock from realns is not cross-node-comparable** without NTP confirmation. Use monotonic timestamps + acquire/release pair-up to establish ordering.

## Test-cluster state at sess21 handoff

- Both .186 + .182 v0.3.54 module loaded, FS shutdown after run 1 iter-4.
- Diagnostic logs in dmesg (will roll over due to peer-discovery noise).
- mkfs_mxfs binary may need rebuild after deploy: `make -C /src/mxfs/tools`.
- Stress: `/tmp/mxfs_stress_v033.sh 15 512 > /tmp/v354_runN.log 2>&1`.
- v0.3.54 baseline distribution: ~iter-2 to iter-4 bnobt LEFT-FAIL each run.
