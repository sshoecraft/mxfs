---
name: sess60-zsl-bmbt-leaf-write-essentially-never-submitted
description: sess60 KEY: P60-BMBTWRITE probe shows ino=131 bmbt-leaf WRITES essentially never reach xfs_buf_submit_bio → leaf flush is MISSING, not a stale clobbe…
metadata:
  type: project
---

## sess60 final finding — the bmbt leaf is barely WRITTEN at all

Current build **3221AE35** (= 8E495999 evict-gate fix + P60-RELAUDIT +
P60-BMBTWRITE write probe). Builds on
[[sess60-zsl-evict-gate-fix-and-stale-leafwrite-residual]].

### NEW DECISIVE DATA (reframes the residual)
Added `mxfs_bmbt_write_probe(bp)` at the single write chokepoint
`xfs_buf_submit_bio` (pal/linux/xfs_buf.c, right after
mxfs_submit_partial_inode_write).  Logs every bmbt-leaf WRITE: owner, daddr,
level, numrecs, owner-incore?, i_dlm_mode.  After a full iters=1 storm
(silent=1600, still shutting down):
```
test1: P60-BMBTWRITE total=0
test2: total=0
test4: total=1  -> owner=139 lvl=0 numrecs=13 incore=1 mode=5(EX)   (NOT 131)
```
**ino=131's bmbt leaf is essentially NEVER written to disk during the storm.**
Yet reloaders read a real leaf value (leaf=17) and a fresh dinode (di=18).  So
the dinode (inode-cluster, di_nextents) is flushed frequently (di keeps
growing, visible cluster-wide) while the LEAF flush lags badly / is skipped.

### REFRAMED ROOT (supersedes the "stale leaf-write clobber" guess)
The on-disk `di_nextents=N` / `leaf=N-1` off-by-one is NOT a stale write
clobbering a newer leaf.  It is a **MISSING leaf flush**: the leaf buffer is
re-dirtied (record N added in-core) but its WRITE never reaches
xfs_buf_submit_bio, so disk keeps the old N-1 leaf while the dinode advances
to N.  The release drain's `mxfs_dir_bmbt_scan(ip, true)` is SUPPOSED to
xfs_bwrite every dirty/in_ail/pinned leaf, and `mxfs_dir_data_durable` loops
until durable — yet the bio never fires for 131.

### NEXT (RULE 4) for next session
1. Confirm the probe placement: does `xfs_bwrite()` from mxfs_dir_bmbt_scan
   actually reach xfs_buf_submit_bio?  Add a pr_warn INSIDE the bmbt_scan
   flush branch (right before/after the xfs_bwrite at xfs_mxfs_dlm.c ~242)
   logging ino + numrecs + werr.  If it logs for 131 but P60-BMBTWRITE
   doesn't, the write is short-circuited between xfs_bwrite and the bio
   (e.g. buffer already DONE/clean, or _XBF_DELWRI_Q requeue, or
   xfs_buf_submit early-return).  If bmbt_scan never even RUNS the flush for
   131, then bmbt_scan's owner-match / needs-check (dirty||in_ail||pinned||
   delwri) is FALSE for the re-dirtied leaf → find why (BLI not attached?
   leaf buffer not in this node's cache? the create's leaf insert logs a
   DIFFERENT buffer instance = aliasing/daddr double-alloc, sess39 family).
2. Likely real fix: ensure the dir release drain flushes the bmbt leaf
   whenever di_nextents advanced — or, simpler, never let xfsaild/iflush
   write the dinode (di_nextents) unless the matching leaf is also being
   landed (ordering: leaf before dinode).

### KEEP (verified-good or harmless this session)
- evict-gate fix (xfs_mxfs_dlm.c ~1685): only evict bmbt children when
  need_iread — stops the iext-loaded leaf revert (PROVEN: di=15/iext=15/
  leaf=15 ok now). KEEP.
- P60-RELAUDIT + P60-BMBTWRITE probes (diagnostics; can stay, rate-limited).
- P60 xfsaild-skip-bmbt guard (never fires; harmless).
- bmbt-FUA add was REVERTED (inert under fua_disable=1).

### INFRA
Each shutdown storm wedges ~9 nodes (umount D-state); virsh -c qemu:///system
destroy+start them, ~12s to recover all 16 + NFS + module.  nohup the
criterion, poll ≥480s.
</body>
