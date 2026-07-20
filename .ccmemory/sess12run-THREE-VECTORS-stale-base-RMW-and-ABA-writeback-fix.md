---
name: sess12run-THREE-VECTORS-stale-base-RMW-and-ABA-writeback-fix
description: sess12(ccloop) dir_reuse loss has 3 stale-base-RMW vectors (ABA-writeback, shortform reconv, intra-create revert). Built EX-gated ABA write-skip fix…
metadata:
  type: project
---

## sess12 (ccloop) — dir_reuse_coherency durable loss is MULTI-VECTOR stale-base RMW

All three are the same disease: a node modifies+destages a dir image missing a peer's committed entries. Manifests at different dir-format stages. (Storage is LIO; fua_disable tested 0 AND 1 — NEITHER fixes it, so it is NOT read staleness. The node uses a stale CACHED buffer/fork it never re-reads.)

### Vector 1 — ABA writeback clobber (block/leaf), multi-entry
PROVEN: `P-LEAFWRITE tag=CLOBBER ... daddr=2093296 buf_cnt=127 disk_cnt=402 bufgen=0 comm=dd` — a STALE dir leaf/data buffer lingering in-AIL from a prior EX tenure is re-flushed by **background xfsaild (comm=dd, file-data writer)** over a daddr a peer grew on disk, dropping 275 hash entries. The dir inode is often RECLAIMED at flush time (in_core=0).

### Vector 2 — shortform→block re-conversion clobber, single/few entries (sess61 family)
PROVEN: lost `node4_f1` was created `P-CRNAME fmt=1` (SHORTFORM). A node with a STALE in-core shortform `i_df` re-converts sf→block (or adds another sf entry) writing ONLY its own entries, dropping the peer's. modify_refresh's `mxfs_dir_evict_data_blocks` only refreshes DATA BLOCKS — for a SHORTFORM dir there are none, so the stale `i_df` fork is used directly with NO refresh. sess61 `mxfs_dir_modify_adopt_disk_format` was refuted (format-compare never fires; divergence is CONTENT-level at equal shortform format). Needs a CONTENT-level shortform reload/merge under ILOCK_EXCL (the down_write(i_lock) reload deadlock is why it's unsolved).

### Vector 3 — intra-create single-dirent revert (sess11 DECISIVE)
A create commits a dirent (rval=0) but it is ABSENT from in-core at durable_signal ~30us later, same thread, ILOCK_EXCL held, gen bumped 4→5 (peer modified during the create). The create's EX-acquire reload/evict interplay reverts the just-added dirent. Not yet fixed.

### FIX BUILT THIS SESSION (build B5FB078A, KEEP, default ON) — addresses Vector 1
New param `dir_ex_write_guard` (default 1). In `pal/linux/xfs_buf.c` (the sess41 dir-write guard block): a dir DATA/LEAF block may only be DESTAGED by the node holding the dir DLM **EX**. When a write is submitted while we do NOT hold EX (`!in_core || i_dlm_mode != MXFS_LOCK_EX`), coherently plain-read the on-disk block; if it PROVES strictly more / divergent dirents (disk_cnt>buf_cnt or equal+fingerprint differ), SKIP the write (emulate clean ioend) — probe `P12-DIR-EXGUARD-SKIP`. SOUND vs the refuted `dataclobber>=2`: legit removes/conversions/fresh-leaf writes ALL run under EX so are NEVER caught (avoids the "keeps the ghost" lookup_fail=150 regression); the disk-proven check prevents false-skips of legit not-EX writes (none exist — modifications are under EX; the release drain is SYNCHRONOUS while still EX, mxfs_dir_flush_data_blocks L1559). Verified no false-skip: mode=3 (non-EX) writes with clobber=false were correctly NOT skipped.

### STATUS: fix is sound but INSUFFICIENT alone — the repro still fails on Vectors 2/3 (single-dirent / shortform). drc4 run after the fix: FAIL round 3 node4_f1 (shortform vector), EXGUARD fired 0× (that round had no ABA clobber). Full 4/tcp suite measurement in progress.

### NEXT
- Vector 2 (shortform): content-level shortform reload/merge on modify when gen advanced (peer modified). The hard part = reload under ILOCK_EXCL without down_write(i_lock).
- Vector 3 (intra-create): instrument EX-acquire/reload timestamp vs addname vs durable_signal (sess11's unfinished decisive probe).
- RULE 5 consult (GPT-5.5 first) is now justified: complete PROVEN multi-vector diagnosis + many refuted approaches (fua_disable both ways, dataclobber>=2, sess61 adopt, sess18 merge). Architectural Q: coherent dir base across shortform+block under ILOCK_EXCL without the reload deadlock.

See [[sess12run-CLEAN-BUILD-4tcp-baseline-two-real-bugs]] [[sess12run-CRITICAL-tcp-cluster-is-LIO-not-SCST-fua_disable-suspect]] [[sess11run-DECISIVE-dirent-absent-at-durable-signal-entry-handoff-during-create]].
</body>
