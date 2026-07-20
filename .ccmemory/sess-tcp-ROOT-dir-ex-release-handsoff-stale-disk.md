---
name: sess-tcp-ROOT-dir-ex-release-handsoff-stale-disk
description: ROOT (proven): cross-boundary shortform-dir rename loses source-removal — reload clobbers uncheckpointed create → removename ENOENT → lost-update OR…
metadata:
  type: project
---

## STATE: criterion "2 node dlm=tcp 100%" NOT met. STABLE build = `E8BF16B2` (local+cluster):
fresh-reboot RUN1 = 15/16 (only crash_consistency 1/2 flaked; tcp_dlm_scaling PASSED). Back-to-back
runs flake on the shared-dir-coherency family (crash_consistency / dlm_fairness / cache_coherency /
tcp_dlm_scaling). Prior baseline 404BC55C ~same. METHOD: `tests/reboot_cluster.sh 2`; then
`./run.sh 2 tcp` (RUN1 usually clean-ish, RUN2+ exposes it). After reboot nodes are UNMOUNTED until
prep_cluster mounts them — that's normal, not a wedge.

## ROOT (PROVEN this session, RULE 4) — cross-DLM-tenure shortform-dir rename loses the SOURCE removal
Test: each node 150x `echo r>f; mv f f.done; rm f.done` in ONE SHARED dir. The leaking round's
`create` and `mv` STRADDLE a dir-EX handoff. Sequence: node creates n_rN (holding EX), is BAST'd
(peer wants EX) BEFORE its `mv`, releases; then re-acquires EX for the `mv`. At the mv's EX
re-acquire, mxfs_dlm_reload_inode rebuilds the SHORTFORM fork from the on-disk dinode — which is
MISSING n_rN because n_rN's create was only LOGGED (CIL), not yet checkpointed to the inode cluster
on the platter. So `xfs_dir_removename(src=n_rN)` (xfs/libxfs/xfs_dir2.c:1647) returns **-ENOENT**
(proven: P-RENAME-SRCDEL rc=-2). TWO manifestations of this same ENOENT:
 (1) durable LOST-UPDATE: target n_rN.done added + rm'd, source n_rN never removed → leftover n_rN
     nlink=1, both nodes agree, survives drop_caches (tcp_dlm_scaling/dlm_fairness "shared dir
     drained got=1"; cache_coherency cross_visibility).
 (2) **FS SHUTDOWN**: removename -ENOENT after the rename already DIRTIED the transaction →
     `xfs_rename` → `xfs_trans_cancel`(dirty) → `xfs_error_report` → shutdown (PROVEN call trace on
     test2: xfs_rename+0x90b → xfs_trans_cancel → unmounted). This is why a bad run shows many tests
     0/2 (one node's FS shut down).

## WHY release-side durability fails (PROVEN, P-ICD probe in mxfs_inode_cluster_durable):
At the dir-EX BAST release, the dir inode is `clean=1` (xfs_inode_clean true: iflushed INTO its
cluster buffer, ili_fields cleared) `rerr=-EAGAIN` (iflush_cluster has nothing to flush) but
`delwri_q=1 in_ail=1 pin=0` — the cluster buffer is still DELWRI-QUEUED and the inode log item is
still IN THE AIL: **the buffer write was never submitted/completed**. So the committed dir image sits
in a delwri-queued buffer (eventually target write-cache), NOT on the PLATTER. Peers FUA-read the
platter (pierces SCST cache) and see the stale image. P-SFREL-VERIFY proved it:
`loopexit_size==incore_size but disk(FUA platter) differs` (NOT a concurrent-mod race — in-core is
stable across the flush). mxfs_inode_cluster_durable's -EAGAIN path just msleep'd hoping xfsaild
submits within 16ms; under churn it does not → returns false having never landed the buffer.

## FIX ATTEMPTS THIS SESSION:
1. BAST-release shortform cluster flush (mxfs_dlm_dir_inode_durable in mxfs_dlm_bast_process ~3608)
   — KEPT (correct direction, harmless, calls proven cluster_durable) but INSUFFICIENT (the
   cluster_durable -EAGAIN gap above means it doesn't actually land the buffer).
2. -EAGAIN "drive the delwri buffer" — TWO variants TRIED, BOTH BAD:
   (a) xfs_ail_push_ag_sync(whole AG) in the retry loop → STALLED cluster (cache_coherency 0/2;
       sess82 warns whole-AG sync push stalls under multi-node). tcp_dlm_scaling passed 3/3 + one
       clean 16/16 run, but cache_coherency/dlm_fairness regressed.
   (b) surgical xfs_buf_delwri_submit / mxfs_dlm_ag_drain_alloc_buflist on the cluster buffer in the
       -EAGAIN path → test2 still shut down (the underlying rename-ENOENT shutdown, not clearly the
       fix). Build 0E611CA4 showed 6 FAIL/many 0/2 = test2 FS shutdown.
   BOTH REVERTED — mxfs_inode_cluster_durable is back to its proven-safe original (-EAGAIN =
   msleep+continue). DO NOT naively re-add whole-AG push (stall) in this hot path.
3. reload self-skip for dirty shortform — REVERTED (Gemini: acquire must blindly reload).

## GEMINI verdict (RULE 5): release MUST make committed dir state durable to PLATTER before dropping
dir EX; acquire then blindly reloads. The concrete gap is real: the release must DRIVE the
delwri-queued inode-cluster buffer to disk (submit + wait + blkdev_issue_flush) WITHOUT a whole-AG
stall. NEXT SESSION DIRECTION (untested): in the cross-boundary case, the cleaner fix may be at the
CREATE side — make n_rN's create durable to the inode cluster BEFORE the dir lock can be released
(so the reload never clobbers it). The create-side barrier mxfs_dlm_dir_inode_durable EXISTS but is
SKIPPED for self-created parents (the shared test dir is mkdir'd by one node then shared; flag clears
on BAST but creates BEFORE the first BAST are unprotected). OR: make xfs_rename robust to removename
-ENOENT on the source (re-lookup / don't dirty-cancel → avoid the SHUTDOWN at least). OR: a reliable
non-stalling per-buffer destage in mxfs_inode_cluster_durable's -EAGAIN path (the delwri buffer must
be submitted by SOMETHING during release; find why xfsaild doesn't and drive just that buffer
without xfs_ail_push_ag_sync). Verify each with `./run.sh 2 tcp` x3 back-to-back (no dirwr) — must be
16/16 every time AND no FS shutdown (watch dmesg for xfs_trans_cancel/Call Trace).

## DIAGNOSTICS (gated mxfs.dirwr=1; P-ICD is UNRATELIMITED+heavy + P-SFREL-VERIFY does per-release
FUA → dirwr=1 HEAVILY perturbs/cascades failures; use ONLY for targeted capture, never to judge
clean rate). P-ICD (mxfs_inode_cluster_durable internals), P-SFREL-VERIFY (incore/loopexit/platter
at dir release), P-RENAME-SRCDEL (rename removename rc). HARNESS (KEEP): run.sh reset_pending (resets
the full to-be-run set to PENDING before prep — user-requested); run.sh+prep_node.sh forward
MXFS_EXTRA_MODARGS for insmod params. See [[sess-tcp-tcp-dlm-scaling-flaky-dir-lostupdate-root]]
[[sess97-gpt-dir-coherency-design]] [[sess88]].
