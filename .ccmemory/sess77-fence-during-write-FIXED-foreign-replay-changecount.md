---
name: sess77-fence-during-write-FIXED-foreign-replay-changecount
description: sess77: fence_during_write FIXED (build 3DC74E7D). Foreign-replay inode skip now uses di_changecount (node-independent) not LSN. PASS lost=0.
metadata:
  type: project
---

## sess77 (run 14d31183) — fence_during_write FIXED → PASS (build 3DC74E7D)

### The fix
In `xfs/xfs_inode_item_recover.c` `xlog_recover_inode_commit_pass2`, the newer-on-disk
skip used `XFS_LSN_CMP(on_disk di_lsn, current_lsn) > 0`. With MXFS per-node log slices
the two LSNs come from independent cycle/block sequences → comparison is meaningless, so
during FOREIGN replay (replaying a dead node's slice) a stale inode record reverts peers'
committed data (the sess76 root cause).

FIX: when `xlog_is_mxfs_foreign_replay(log)` is true, skip the replay if
`be64_to_cpu(dip->di_changecount) >= ldip->di_changecount`. di_changecount = VFS i_version,
force-incremented on every dir/inode modify (XFS_ILOG_CORE set; reloaded from disk on DLM
reload via inode_set_iversion_queried) → globally monotonic per-inode across all nodes,
unlike per-slice LSN. Non-foreign (mount-time own-slice) replay keeps the original LSN path.

### Proof (RULE 4, single trace via P77-FRINODE probe, gated behind mxfs_instr)
`KILL_AT=30 tests/diag_fence_visibility.sh --nodes 4`, dmesg on replaying node test1:
- The ONE reverting record: `ino=131 disk_di_lsn=0x100000004 cur_lsn=0x100000004 lsn_cmp=0
  disk_cc=7 log_cc=5 verdict=SKIP`. lsn_cmp=0 means OLD code (`>0` false) would have APPLIED
  the dead node's stale image (cc=5, pre-n2/n4) over the on-disk cc=7 (peers added n2/n4) →
  reversion. New code: 7>=5 → SKIP → peers' data preserved.
- All 219 other records APPLY correctly (test3's own n3 subdir ino=2097280 cc 139→146, plus
  its 200 new files cc=0). So legitimate dead-node data still replays.

### Validation
- `tests/diag_fence_visibility.sh KILL_AT=30`: all 4 subdirs n1..n4 visible 200/200, live AND
  after drop_caches.
- `fence_during_write --nodes 4`: RESULT PASS lost=0 (×2, both builds D5530967 ungated and
  3DC74E7D gated).
- crash_consistency (also uses foreign replay): [verifying — no regression expected: a
  sole-writer dead node has disk_cc=0/low < log_cc → APPLY, unchanged].

### State after sess77
- Build `3DC74E7D` deployed (NFS /src). fence_during_write now PASS.
- Remaining FAILs: `posix_semantics_multi16` (>600s), `rsync_paired` (148%). zero_silent_loss
  PASS (sess76 fix held). Marker NOT written.
- NEXT: posix_semantics_multi16 timeout root-cause, then rsync_paired perf.

Related: [[sess76-fence-foreign-replay-reverts-peer-dir-LSN-noncomparable]]
[[sess76-readahead-hold-leak-umount-wedge-FIXED-zsl-passes]]
[[sess17-crash-consistency-root-and-foreign-replay-design]]
</body>
