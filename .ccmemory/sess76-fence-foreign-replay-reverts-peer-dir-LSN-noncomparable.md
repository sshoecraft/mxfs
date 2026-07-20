---
name: sess76-fence-foreign-replay-reverts-peer-dir-LSN-noncomparable
description: sess76: fence_during_write ROOT = foreign journal replay of dead node reverts peer-committed shortform-dir changes; per-node log-slice LSNs non-compa…
metadata:
  type: project
---

## sess76 (run 14d31183) — fence_during_write ROOT diagnosed (NOT yet fixed)

### Symptom
`fence_during_write --nodes 4` FAIL lost=400: test2 & test4 each wrote+fsync'd 200 files into their own subdir of shared parent `fence_test`, but after test3 (victim) is fenced, NODE0 (and the WRITERS THEMSELVES) see 0 files AND the n2/n4 subdir entries vanish from `fence_test`. drop_caches does NOT recover → DURABLE loss, not cache lag.

### Decisive repro (tests/diag_fence_visibility.sh, KEEP)
- Kill victim AFTER it finishes (progress=200) → all survivors visible 200/200 (PASS-like).
- Kill victim EARLY mid-transaction (KILL_AT=30, progress≈145, holding/cycling dir locks) → n2/n4 + their files GONE durably; `ls fence_test` shows only n1 + partial n3.
So the bug needs the victim fenced WHILE actively modifying the shared parent dir.

### ROOT (proven by dmesg recovery trace)
test1 (slot 0, lowest live) is elected to replay the DEAD node's journal slice: `mxfs_dlm_foreign_replay_work_fn -> mxfs_xlog_recover_foreign_slice (xfs/xfs_log.c:721) -> xlog_recover(shadow)` over test3's slice. test3 had RELEASED EX on `fence_test` after its mkdir n3 (letting n2/n4 in), but test3's on-disk journal still carries its stale `fence_test={.go,n1,n3}` image. Replay re-applies it, reverting peers' committed n2/n4.

`fence_test` is a tiny (5-entry) SHORTFORM dir → stored IN the inode → recovered via INODE recovery (xfs/xfs_inode_item_recover.c:394-402). That skip is:
`if (XFS_LSN_CMP(on_disk dip->di_lsn, current_lsn) > 0) skip;`
with `current_lsn` = test3's log-record LSN and on-disk `di_lsn` = LSN stamped by test2/test4. **MXFS uses PER-NODE log slices** (each `daddr = logstart + (slot%node_count)*slice_bblks`, independent cycle/block numbering via xlog_alloc_log). So the two LSNs are from independent sequences — `XFS_LSN_CMP` is meaningless → the skip fails → stale test3 inode overwrites peers' newer one. This is the same class as sess17 "foreign-replay 3 of 6 incomplete".

Why zsl PASSES but fence doesn't: zsl's verify does `sync; echo 3 > drop_caches` then counts (cold read), and in normal storms the LAST EX-writer (fresh base) always overwrites → on-disk converges correct. Fence FREEZES test3's stale version via replay (no later writer; victim dead) → durable.

### FIX LEAD (not yet implemented — RULE 4: instrument+prove first next session)
Use a NODE-INDEPENDENT ordering for the foreign-replay skip. Both on-disk `dip->di_changecount` (xfs_format.h:959) and log `ldip->di_changecount` (xfs_log_format.h:448) exist. di_changecount is per-inode monotonic across all nodes (incremented per modify after reading current). Proposed: in inode recovery, WHEN `XLOG_MXFS_FOREIGN_REPLAY` is set on the log (shadow->l_opstate, set in mxfs_xlog_recover_foreign_slice), skip the replay if `on_disk di_changecount >= ldip->di_changecount` (on-disk content is same-or-newer). Must also handle the analogous block-format dir / AG-meta buffer recovery path (buffers use embedded LSN via xlog_recover_get_buf_lsn — needs a node-independent generation too; dir3/AG blocks may not have a changecount → harder; bound first by proving the shortform inode path fixes fence_during_write).

NEXT SESSION:
1. Instrument xfs_inode_item_recover.c skip (gate on foreign replay): log ino, on_disk di_lsn, current_lsn, LSN_CMP verdict, on_disk di_changecount, ldip->di_changecount. Run tests/diag_fence_visibility.sh KILL_AT=30. Confirm fence_test inode is APPLIED (not skipped) while on_disk changecount > logged changecount.
2. If proven, add the foreign-replay changecount skip. Re-run fence_during_write --nodes 4 (expect lost=0). Watch crash_consistency doesn't regress (it also uses foreign replay).
3. Then posix_semantics_multi16 (>600s) and rsync_paired (148%).

Build at boundary: EAE5F4C0 (zsl fix) + P-DRAINSTUCK probe. Related: [[sess76-readahead-hold-leak-umount-wedge-FIXED-zsl-passes]] [[sess17-crash-consistency-root-and-foreign-replay-design]]
