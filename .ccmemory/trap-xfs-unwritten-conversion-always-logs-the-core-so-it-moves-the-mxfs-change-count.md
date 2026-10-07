---
name: trap-xfs-unwritten-conversion-always-logs-the-core-so-it-moves-the-mxfs-change-count
description: TRAP: unwritten->written conversion logs XFS_ILOG_CORE unconditionally (xfs_bmapi_convert_unwritten), so MXFS's forced bump moves di_changecount
metadata:
  type: feedback
---

**What bit:** I hypothesised that an in-size unwritten->written conversion logs only the data fork (xfs_bmap_add_extent_unwritten_real returns XFS_ILOG_DEXT when the extent count is unchanged), so on a clustered mount di_changecount would not move (MXFS forces one bump per transaction only when XFS_ILOG_CORE is logged, xfs/libxfs/xfs_trans_inode.c), and the foreign replay's changecount gate / P-RELOAD-IDENTICAL would drop the conversion (fsynced data reading back as zeros). Wrote tests/pve_unwritten_live.sh and tests/pve_unwritten_replay.sh for it. FALSE.

**Why:** xfs/libxfs/xfs_bmap.c xfs_bmapi_convert_unwritten: "Log the inode core unconditionally in the unwritten extent conversion path ... if the extent count hasn't changed" -> `bma->logflags |= tmp_logflags | XFS_ILOG_CORE` (not for the COW fork). So every conversion transaction logs CORE and takes MXFS's forced bump. Verified live on the physical pair 0.90.90 (2026-10-07): pve1 loaded the map, pve2 grew the written extent 31 times with O_DIRECT + fdatasync, pve1 read all 32 blocks intact (tests/evidence/pve_unwritten_live/20261007T080807Z-192.168.1.80, re-read after a clyde stall).

**What does NOT bump the count:** timestamp-only logs (XFS_ILOG_TIMESTAMP from xfs_vn_update_time) and the release drain's re-log (deliberately suppressed). Those are what the foreign replay's P77-STALE-BASE-VERDICT "buf_cc > platter_cc, log_cc == buf_cc, SKIP/SKIP" lines are: later images of the same count after the replay's own earlier APPLY in the same pass.

**Test-design trap that would have masked it either way:** a sequential-conversion test must leave an unwritten tail past the last block written. Writing to the very end of the fallocated range makes the last conversion merge the two extents into one (count changes, core logged, count bumped), and that last image carries every block.

**How to apply:** before claiming a changecount-gate hole for some transaction type, read the XFS caller that commits it for an unconditional XFS_ILOG_CORE (bmapi convert, size updates, nblocks changes all log core); check the claim with the P77-FRINODE probe (pr_debug, `echo 'format P77-FRINODE +p' > /proc/dynamic_debug/control`) rather than by reasoning.
