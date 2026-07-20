---
name: sess96_lessons
description: sess96 — typeflip-ftype fix KEEP (unlink thrash 146s→28s). PROVEN lost-update root=local pinned-stale dir buffer. FUA-on DISPROVEN (slow+worse).
metadata:
  type: project
---

# sess96 (2026-06-05, ccloop run 29df431e)

## Build state
- **Current deployed build: `FB9573F7`** = sess95 + the sess96 typeflip-ftype fix. KEEP.
- `fua_disable=1` is the correct module default (see FUA finding below). Restored on all nodes.

## WIN: typeflip-ftype fix (KEEP, in FB9573F7)
Threaded authoritative `dirent_ftype` into `mxfs_dlm_reload_inode(ip, uint8_t expect_ftype)`
(header xfs_mxfs_dlm.h:130 + def ~1861). In the sess90 typeflip-stale guard (~2013), BYPASS
the skip when `xfs_mode_to_ftype(disk di_mode) == expect_ftype` (disk+dirent AGREE = genuine
reuse, not a torn read). Added `RELOAD-TYPEFLIP-DIRENT-OK` probe. P95-TYPEFLIP site
(xfs_inode.c:908) passes `dirent_ftype`; all other callers pass `XFS_DIR3_FT_UNKNOWN`.
RESULT: eliminated the uv_verify typeflip THRASH — unlink_visibility 146s timeout → 28s.

## cache_coherency CURRENT STATE (still FAIL, but small)
- cross_visibility PASSES. rename/unlink/cross_write_read fail with SMALL counts under
  fua_disable=1: rename **2/240**, unlink **2/122**, cwr **1/6**. Durable lost-update on a
  SHARED directory under 4-node concurrent rename. (Intermittently a bnobt double-free
  `ltbno+ltlen>bno` in xfs_free_ag_extent shuts the FS down ~1 run in 2 — separate blocker.)

## PROVEN ROOT of the 2-fail lost-update (RULE 4, instrumented)
`node4_after_1` (node4's FIRST rename) durably invisible to ALL 4 nodes incl. node4.
Mechanism = **local pinned-stale dir-buffer reuse**: probe
`DIR-STALE-SKIP ino=136 blk=0 buf_gen=0 inode_gen=8..11 pin=1 disk_differs=1 dirty=0
in_ail=0 bli_flags=0x2(DIRTY)` fires on test2(10x)/test4(8x). The read-time invalidation
in xfs_da_btree.c (~2985) takes the SKIP branch (3001) when the cached dir buf is
pinned/dirty/in-AIL — it CANNOT re-read a pinned buffer (sess64 PROVED re-reading a
pinned buf races writeback → xfs_inode_buf_verify corruption + shutdown). So the node
keeps its stale local buffer, RMWs it, and on checkpoint durably clobbers a peer's
committed dirent. The buffer is pinned = the node's own CIL-committed-not-checkpointed work.

## Gemini consult ×2 (RULE 5)
Root per Gemini: `xfs_log_force(mp, XFS_LOG_SYNC)` does NOT synchronously wait for unpin —
the iclog IO completes, then the ASYNC `xlog_cil_committed` workqueue drops pin_count + AIL-
inserts. The bounded BAST-release drain (msleep(2), w<100 = ~200ms) gives up before the WQ
runs → releases with a pinned dir block → mxfs_dir_evict_data_blocks SKIPS it (P-EVICT-SKIP)
→ next acquirer reuses stale. Gemini said: deterministic unpin via `xfs_buf_wait_unpin`,
release-side, off the CAW bast thread; acquire-side fix is FATAL (clobbers peer).

## TRIED & REVERTED: deterministic flush+evict on release (build FB8842FD)
Added `xfs_log_force(SYNC)+mxfs_dir_flush_data_blocks(ip)` before the evict in
mxfs_dlm_bast_process (~1359). Eliminated DIR-STALE-SKIP/P-EVICT-SKIP (→0), BUT made
rename WORSE **2→24** (node4 lost ALL 20 renames on every node). WHY:
`mxfs_dir_flush_data_blocks` does `xfs_bwrite` which **WRITES THE LOCAL (possibly stale)
buffer to the shared SCST target**, clobbering the peer's committed entries; aggressive
evict then caused more stale rereads. **xfs_bwrite of a dir block on release is WRONG** —
it propagates a stale local copy. REVERTED (back to FB9573F7).

## TESTED & DISPROVEN: fua_disable=0 (FUA reads ON)
Hypothesis "FUA pierces the cache → coherent rereads" is FALSE. rename_visibility alone with
FUA on = **370s (45x slower → timing FAIL) AND 40 failures (WORSE than 2)**. FUA reads the
**STALE PLATTER** (writes sit in the SCST write-back cache; the normal dir BAST-release path
has NO `blkdev_issue_flush` to destage — only the noino path at ~1749 does). So
**fua_disable=1 (plain reads from the shared WB cache) is genuinely the correct/better mode.**
Do NOT re-enable FUA. (Confirms sess62 "FUA reads stale platter on SCST".)

## SYNTHESIS — the real shape of the blocker
Under fua_disable=1 the shared SCST WB cache IS coherent for plain reads. The remaining
lost-update is purely a LOCAL stale-buffer problem: a node modifies a dir block from a
STALE local read (DIR-STALE-SKIP, pinned) instead of re-reading the peer's committed
version. The block-level RMW then clobbers the peer. Fix must make every dir-MODIFYING
read fresh, WITHOUT (a) re-reading a still-pinned buffer (corrupts) and WITHOUT (b) writing
the stale local buffer to the target (clobbers).

## NEXT-STEP HYPOTHESIS (precise, for next session)
At the DIR-STALE-SKIP point in xfs_da_btree.c (~3001), when the cached dir buf is pinned +
gen-stale, DON'T keep it. Instead: `xfs_log_force(mp, XFS_LOG_SYNC)` then
`xfs_buf_wait_unpin(cbp)` (WAIT for THIS buffer's own pending commit to land+unpin — this is
the node's OWN prior work, so landing it is correct and does not clobber), THEN clear
XBF_DONE + re-read fresh (now safe: no longer pinned; gets the merged-latest from the WB
cache). Differs from sess64's corrupting "re-read WHILE pinned" — we wait for unpin FIRST.
Differs from the reverted release-flush — we do NOT xfs_bwrite the local buffer; the
log/AIL writes the node's own committed copy naturally, and the re-read pulls the peer's.
Risk: xfs_buf_wait_unpin can wedge if CIL can't push (sess82) — the prior xfs_log_force
mitigates; this is the read path (process ctx, can block). Build, deploy (reset4 keeps
fua_disable=1 default), run cache_coherency; watch rename 2→0 and that it stays fast (~9s).
If it regresses or wedges → escalate to ask_gpt (2 Gemini already spent on this issue).

## Infra notes
- reset4 sets fua_disable=1 (module default); INSMOD_OPTS does NOT work (prep_tcm_node.sh
  insmods first w/o opts). To test fua_disable=0: runtime `echo 0 >
  /sys/module/mxfs/parameters/fua_disable` on each node (ATOMIC single-cmd ssh; multi-stmt
  ssh aborts early). It's read per-buffer-read so runtime flip engages.
- Single subtest: `MXFS_TESTS_DIR=/src/mxfs/tests MXFS_NODE_OFFSET=16 tests/run_tests.sh
  --nodes 4 --phase cluster --test test_rename_visibility --pass-file /tmp/.mxfs_pass
  --device /dev/sda --mount-point /mnt/shared`. (Default MXFS_TESTS_DIR=/mnt/mxfs-src/tests
  is often NOT mounted; /src IS NFS-mounted on nodes → use /src/mxfs/tests.)
- `make clean` wipes tools → mkfs_mxfs missing → reset4 mount fails with stale-FS recovery
  corruption. After `make clean && make modules` ALWAYS `make tools` too.
- EXIT=137 on a cache_coherency run = SIGKILL (blew the 900s budget, e.g. FUA-on slowness);
  leaves orphaned run_tests + unmounted nodes. `pkill -9 -f run_tests` + reset4.
