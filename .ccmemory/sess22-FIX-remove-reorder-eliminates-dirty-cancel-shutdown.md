---
name: sess22-FIX-remove-reorder-eliminates-dirty-cancel-shutdown
description: sess22(ccloop) FIX build 42A12E6B: reorder xfs_dir_remove_child non-dir path so xfs_dir_removename runs FIRST (clean trans) — eliminates the 8/tcp di…
metadata:
  type: project
---

## sess22 (ccloop) — remove-reorder fix kills the catastrophic shutdown

Build **42A12E6BD498D6BE73F92E9** = keeper 7B66691E + sess21 diagnostics + this fix. KEEP.

### Root of the 8/tcp dir_reuse 0/8 CASCADE (PROVEN, RULE 4):
- test1 (rank1, the SOLE rm-rf'er) hit `XFS (sda): Corruption of in-memory data (0x8) detected at xfs_trans_cancel+0x15e (xfs_trans.c:1061). Shutting down filesystem.` via `xfs_remove+0x2b2 -> xfs_trans_cancel`.
- MX-INSTR: `remove dp=131 ip=10485897 name="node6_f24.md5" xfs_dir_removename rc=-2` (-ENOENT).
- xfs_remove's revalidate guard (xfs_dir_lookup_locked @ xfs_inode.c:3849) FOUND the entry (cur_ino matched), but `xfs_dir_remove_child` (xfs_dir2.c) dirties the trans (xfs_trans_log_inode(dp,CORE) + xfs_droplink(ip)) BEFORE calling xfs_dir_removename, which returns -ENOENT → dirty cancel → SHUTDOWN → EIO on all writes → cascade 0/8.
- Only rank1 does rm-rf (peers idle at barrier) → NOT a concurrent same-entry race. It's node1's OWN in-core dir being inconsistent: leaf-hash entry present, data-block dirent absent.

### THE FIX (xfs/libxfs/xfs_dir2.c xfs_dir_remove_child):
Reorder the NON-DIRECTORY branch so `xfs_dir_removename` runs FIRST, while the transaction is still CLEAN. removename returns -ENOENT atomically (its internal lookup fails before modifying/logging any dir buffer), so a clean-trans cancel is benign (rm gets -ENOENT, node stays up). Only after removename succeeds do we log dp CORE + ichgtime + droplink(ip). The S_ISDIR branch keeps upstream ordering (emptiness pre-validated; ".."/"." droplinks must precede). Removed the now-wrong `ASSERT(error != -ENOENT)`.

### RESULT: SHUTDOWN ELIMINATED.
8/tcp dir_reuse went from 0/8-cascade-shutdown to all 8 nodes completing all 24 rounds with structured FAIL (no EIO, no cascade). NEW residual = the underlying coherency bug, now cleanly visible: `readdir count exp=800 got=802/803/804/798` (count DRIFT) + `leaf-hash lookup_fail` (entry in data block / readdir but not lookup-able via leaf hash). All nodes report identical counts (shared-dir, consistent). 

### NEXT: fix the leaf/data inconsistency. Hypothesis: mxfs_dlm_dir_modify_refresh (xfs_inode.c:3845, runs before each unlink) drops/re-reads stale DATA blocks but NOT the LEAF index → leaf and data drift during rank1's sole-writer rm-rf. The -ENOENT skip now leaves phantom leaf entries that accumulate → readdir>800. Investigate mxfs_dlm_dir_modify_refresh scope (data-only vs leaf too).
