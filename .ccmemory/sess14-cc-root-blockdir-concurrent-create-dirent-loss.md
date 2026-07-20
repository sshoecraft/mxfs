---
name: sess14-cc-root-blockdir-concurrent-create-dirent-loss
description: sess14 PROVEN: crash_consistency 2/tcp blocker = BLOCK-format-dir concurrent-create durable dirent LOSS (a peer's RMW clobbers an entry). node2_f49 l…
metadata:
  type: project
---

## sess14 DECISIVE (tests/cc_blockdir_probe.sh, build 3017D9DF). crash_consistency is now THE 2/tcp blocker (3/6 fail in validation; dlm_fairness 6/6 FIXED by SF merge).

## REPRODUCER + RESULT: each node writes 50 data (oflag=sync) + 50 .md5 into ONE shared dir (=200 entries = BLOCK/LEAF format). Concurrent. Then test1 readdir-counts.
- all=199/200: **node2_f49 (test2's OWN data file) MISSING**.
- pureLUN (drop_caches+reread): still 199.
- direx (test1 touch -> dir-EX acquire -> BAST test2 -> drain -> reread): still 199.
- **test2 ALSO sees 199/200; test2 has node2_f49 = N** (test2 lost its OWN file!).
- +8s: still 199 (NOT eventual).
- node2_f49.md5 EXISTS (md5=100/100) — only the DATA-file dirent was clobbered, its sidecar survived.

## DIAGNOSIS: durable BLOCK-format-dir concurrent-RMW lost-update. test2 created node2_f49; a concurrent block-dir RMW (by test1 adding node1_fXX, OR a stale-base reload) overwrote the dir data block, dropping node2_f49's dirent durably (both nodes read the same clobbered LUN block). Same ROOT CLASS as the shortform resurrection (stale-base RMW of a shared dir) but: (a) BLOCK format (data blocks + hash btree, NOT inline dinode), (b) symptom is LOSS not resurrection. The sess14 3-way SF merge ONLY handles XFS_DINODE_FMT_LOCAL — block dirs go through xfs_da_read_buf gen-invalidation (laggy heartbeat gen) + mxfs_dir_evict_data_blocks, NOT the merge.

## WHY direx didn't fix: the entry is genuinely gone from the LUN (not test1-cache-stale, not test2-journal-only — test2's drain on BAST would have flushed it; it's already clobbered durably). So it's a true write-side loss, not a visibility lag. [supersedes the read-side-lag hypothesis in [[sess-tcp-cc-ROOT-dir-entry-visibility-lag]] for THIS build]

## FIX DIRECTION (next): block-format-dir concurrent-modify coherency = ensure a block-dir RMW (xfs_create/remove into a shared block dir) works from a FRESH base = the peer's durable dir block, by forcing eviction+re-read of the target dir data block before the RMW when a peer may have modified it (analogous to the SF merge but for block dirs). Touchpoints: xfs_da_read_buf gen-invalidation (xfs/libxfs/xfs_da_btree.c ~3033), mxfs_dir_evict_data_blocks, the dir-EX fast-path in mxfs_dlm_ilock_begin (block-dir equivalent of sf_disk_check). A true 3-way merge for block dirs is very complex; prefer reliable reload-before-RMW. CAUTION (sess9): forcing slow-path on every op -> starvation; per-op FUA -> rsync timing wall.

## ALSO: validation iter4 had a CASCADE (cc + fence_during_write 0/2 + fault_netpartition 0/2 + soak + tcp_dlm_scaling 0/2) = possible cc-induced node wedge/shutdown contaminating later tests. Verify NOT merge-induced (dlm_fairness 6/6 argues merge is stable; cascade likely cc clobber -> EFSCORRUPTED shutdown). Add shutdown/oops capture. [[sess14-merge-engages-writeside-cc-is-readside-blockdir]] [[sess14-IMPL-3way-sf-merge-build-917BE2AD]]
