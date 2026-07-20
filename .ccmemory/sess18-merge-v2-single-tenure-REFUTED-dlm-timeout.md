---
name: sess18-merge-v2-single-tenure-REFUTED-dlm-timeout
description: sess18 (ccloop): merge v2 single-tenure (xfs_trans_roll, ONE ilock) ALSO shuts down — DLM acquire TIMEOUT (rc=-110) on hot dir ino, not churn. Merge-…
metadata:
  type: project
---

## sess18 (ccloop run 8ddb16a2) — merge v2 REFUTED. Build B0C5862 (xfs_mxfs_dlm.c Phase 2 rewritten: single ILOCK_EXCL tenure held across all re-adds via xfs_trans_roll_inode, ijoin lockflags=0; one DLM acquire instead of v1's per-entry). dir_merge=1.

## RESULT: SAME FS SHUTDOWN as v1, at iter 1 (ino=131, the hot shared dir). dmesg:
- test1: `DLM inode lock failed: ino=131 mode=5 rc=-35` (EDEADLK, handled via BAST-drain+retry) THEN `mode=3 rc=-110` (ETIMEDOUT) ×3 → `DLM inode lock unrecoverable: ino=131 mode=3 rc=-110 — shutting down` at mxfs_dlm_ilock_begin+0xbc6 (xfs_mxfs_dlm.c:8159, SHUTDOWN_CORRUPT_INCORE). Both nodes' mounts dead; ssh alive.

## ROOT OF THE FAILURE (refines v1 analysis): it is NOT transaction churn. It is that the merge takes an EXTRA dir-EX DLM acquire on the HOTTEST inode (the shared dir both nodes hammer with concurrent create). mxfs_dlm_ilock_begin (xfs_mxfs_dlm.c:8146-8161) force-shuts-down on ANY non-EDEADLK acquire failure; under 2-node contention the TCP DLM acquire TIMES OUT (-110) → fatal. v1 (per-entry acquire) and v2 (single-tenure, one acquire at pre-lock 1305) BOTH add EX-acquire pressure on ino=131 → timeout → shutdown.

## CONCLUSION: **merge-via-separate-lock-tenure is a DEAD END.** Any approach that acquires the dir-EX DLM grant OUTSIDE the create's own single acquire over-contends the hot dir inode → ilock_begin timeout shutdown. The merge, IF done at all, must reuse the create's ALREADY-HELD grant (no new acquire) — i.e. fold into the create's transaction `tp` at xfs_inode.c:1374 (dp ILOCK_EXCL held, grant cached EX), bounded entry count + reservation headroom. But that has the EEXIST/reservation/dirty-cancel blocker [[sess17-merge-impl-approach-and-txn-blocker]].

## PIVOT (next): Approach A = release-side flush-then-INVALIDATE (GPT demote-drain-by-ownership, called "the sound path" in [[sess17-CONFIRMED-staleflush-clobber-P17]]). The BAST release path (xfs_mxfs_dlm.c ~3980-4098) already loops until data_durable (xfs_bwrite every dir DATA block) holding the grant — NO extra DLM acquire, NO transaction. After that drain, INVALIDATE all dir DATA blocks (clear XBF_DONE) so the next acquire cold-reads the peer's union image. The clobber persists because the acquire-side keep-guard (mxfs_dir_evict_data_blocks ~2044) KEEPS an undestaged block that's stale vs peer; if release fully destages+invalidates, the block is never undestaged at next acquire → no keep → cold-read adopts peer. Risk: the post-bwrite/pre-AIL-trim window where mxfs_dir_buf_is_undestaged still reads true. Investigate whether release path evicts after the drain (reading 4196-4360 now).

## Build B0C5862 source change (Phase 2 single-tenure) is GATED behind dir_merge=0 default → DORMANT/safe; can stay in tree. Cluster needs recovery (fresh prep / virsh). [[sess17-merge-v1-REFUTED-dlm-shutdown]] [[sess17-FIX-PLAN-blocklevel-dirent-merge]]
