---
name: sess22-readdir799-is-content-divergent-clobber-count-guards-blind
description: sess22(ccloop) KEY: dir_reuse readdir=799 durable loss is a CONTENT-divergent clobber (under-EX stale-base RMW replaces a peer's entry, count stays e…
metadata:
  type: project
---

## sess22 (ccloop) — readdir=799 is a CONTENT-divergent clobber; count-based guards are blind

### Built P22-DATA-CLOBBER probe at the release-drain bwrite (xfs_mxfs_dlm.c:1616): coherent-read on-disk DATA block, compare LIVE-DIRENT COUNTS in-core vs disk, log if in-core<disk. Then reverted (count-blind). Build 4E6BD15D (probe) → reverted to keeper EFBB9861.

### RESULTS (8/tcp dir_reuse, readdir=792/799 reproduced):
- **P22-DATA-CLOBBER fired ONLY on test1, comm=rm** (rank1 rm-rf: in-core 1 behind disk = LEGIT removes, expected — NOT clobbers). **0× during the create wave on ALL nodes.** → the durable loss is NOT a count-reducing release-drain write.
- **P-DATACLOBBER-SKIP (mxfs_dir_ex_write_guard, default ON, the xfsaild ABA-clobber guard at the bio chokepoint pal/linux/xfs_buf.c:2319) fired 0× on ALL nodes** → the guard's `dir_not_held_ex && disk_cnt>buf_cnt` predicate never matched.

### CONCLUSION (decisive narrowing):
The durable data-block loss is a **CONTENT-divergent, COUNT-preserving clobber**: a node holds dir EX, RMWs a STALE in-core base (missing a peer's entries that ARE durable on disk), its add REPLACES the peer's entry in the block → on destage, count stays equal/close (so `in-core<disk` and `disk_cnt>buf_cnt` are both FALSE) but a peer's dirent is durably dropped. EVERY existing guard is COUNT-based (P22 release count, ex_write_guard disk_cnt>buf_cnt, dataclobber) → ALL BLIND to it. It's under-EX (ex_write_guard's EX-gate skips it). Confirms the sess41 "240× bgen==dir_gen, both tenure tokens read current, write-side guard cannot catch" case — and the evict-side refresh (mxfs_dirrefresh) that was meant to catch it is default OFF ("content-compare fired 0x — wrong target").

### NEXT (two viable directions):
1. **CONTENT/superset write guard**: at the dir DATA-block destage (release bwrite AND/OR the bio chokepoint), coherent-read disk and check whether the in-core block being written is a SUPERSET of the disk block's live dirents (by inumber/name). A legit create/RMW under EX with a fresh base is a superset; a stale-base clobber DROPS a disk entry (not a superset) → skip/refuse the write (let disk's version stand) OR re-read+merge. Must handle the dir_reuse inode#/daddr REUSE ghost (sess41 refutation): gate on same incarnation (b_mxfs_dir_incarn == i_generation) so a prior-incarnation ghost at a reused daddr is NOT treated as authoritative.
2. **Fix the under-EX stale base at the SOURCE**: the acquire/modify evict KEEPS a stale in-core data block (the RMW base). Find WHY this specific block is kept (it's not in-AIL-undestaged per sess41 refresh, not LOCKED-SKIP per 0× P-DE-BLK). Add a content-superset evict refresh: on modify, if the in-core data block is NOT a superset of disk (same incarnation), force re-read. Refreshing the base before RMW is always correct (sess41 principle).

### dir_reuse residual is ONLY this face now (leaf-hash lookup_fail HEALED by sess22 datascan). See [[sess22-readdir799-durable-datablock-clobber-diagnosis]] [[sess22-FIX-node-format-datascan-leafhash-heal]] [[sess22-SESSION-SUMMARY-net-progress]].
