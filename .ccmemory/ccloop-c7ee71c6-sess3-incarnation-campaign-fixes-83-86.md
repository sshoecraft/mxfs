---
name: ccloop-c7ee71c6-sess3-incarnation-campaign-fixes-83-86
description: sess3: corpse-dir root (INACT unlock before mode=0 landed) FIXED via defer+poison; dirent-loss chain (P119 phantom retire + CLMERGE DEADINCARN overla…
metadata:
  type: project
tags: [dir_reuse, incarnation, phantom-retire, clmerge, tcp]
---

# ccloop c7ee71c6 session 3 — incarnation-coherence campaign (v0.11.83-86)

Full detail in /src/mxfs/state.md (same-day). Compact index:

## Proven roots + fixes (all RULE-4 evidence-backed)
1. **Corpse-dir catastrophe** (run 140939Z r1: all-8-nodes EUCLEAN, dir data block = cache_coherency payload "content_1_1" on platter): enabler = `xfs_inactive` released the freed ino's DLM slot while mode=0 was CIL/AIL-only (ifree_eager_durable=0) → peer certified corpse alive (test2 held PR 297s across rmdir). FIX-1: `mxfs_inact_defer_unlock=1` — defer unlock while undestaged; bast durable loop extended to freed inodes; evict path already sound (reclaim⇒flushed).
2. **Phase A poison** (RULE-5 GPT design): MXFS_IF_INCARN_STALE bit 24 (+IRECLAIM_RESET), P34H-INCARN-POISON at 3 reload sites (clean shell + disk-free-genmismatch / cross-incarn fresh), op-entry -ESTALE (lookup/create/remove/rename/readdir), P34H-POISON-EVICT retire+re-iget trap. P34G removed (was wrong-sided).
3. **Dirent-loss chain** (r4 node1_fN loss): three stacked mechanisms, each proven then fixed:
   a. P119-NONEX/P17B skips complete iflush WITHOUT copy-in but flush_out still moves fields→last_fields → next buffer-write ioend retires item = **phantom AIL retire**. Fix: skips gated on `i_dlm_demoter==NULL` (active demote = sanctioned).
   b. Release durable loop trusted "EAGAIN + !in_AIL ⇒ durable". Fix: P146V-UNLANDED — compare cluster-buffer dinode identity (gen/mode/nlink/size/fmt) vs in-core; mismatch → re-log core via tr_ichange txn, retry.
   c. **P-CLMERGE-DEADINCARN** (submit-side overlay in mxfs_iflush_cluster_merge_dirs) re-wrote the dead disk incarnation over the freshly-flushed NEW one (its "local never ahead of disk" premise died with eager=0). Fix: `authorit` mask — slots with same-tenure dirty provenance (dirty_seq==ex_grant_seq) exempt (P-CLMERGE-AUTH-KEEP).
   d. Reload TOCTOU (read pre-drain, adopt post-drain): P34J-RELOAD-DEMOTE-BAIL at entry + pre-adopt epoch/demoter recheck (P34J-RELOAD-RACE-BAIL).
4. Result on v0.11.86: dirent-loss GONE (29/30 checks pass; only pace fail 4 rounds/101s) but 2/3 runs WEDGE in round-1 verify: single dabuf HOLE (`XFS_DABUF_MAP_HOLE_OK` da_btree.c:2909) on one node → syscall loops → barrier DNF. HOLE class pre-exists .86.

## Key mechanics (debugging gold)
- flush_out in xfs_iflush_int runs fields→last_fields EVEN ON SKIP; xfs_buf_inode_iodone retires on last_fields alone. Any new skip path = phantom-retire factory.
- mxfs_partial_iwrite omission classes vs blanket iodone retire is an unresolved tension (logged slots always written today).
- kernlogs are dmesg-since-boot: ALWAYS timestamp-filter; caps/ratelimits go blind — use watch_ino-gated probes (PW-IABORT/PW-ADOPT exist; test arms watch_ino per round).
- P146-RELDUR decode: flushed=1 wrote=0 rerr=-11 = the trust exit.
