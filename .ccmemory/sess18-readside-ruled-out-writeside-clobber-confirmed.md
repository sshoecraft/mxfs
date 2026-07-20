---
name: sess18-readside-ruled-out-writeside-clobber-confirmed
description: sess18: 2/tcp durable dir loss is PURELY WRITE-SIDE clobber, NOT read-side. FUA reads (fua_disable=0) still lose (iter4). Release path does NOT escap…
metadata:
  type: project
---

## sess18 (ccloop 8ddb16a2) — two refutations + mechanism pin-down for 2/tcp crash_consistency durable dirent lost-update. Build B0C5862 (== 492C8EB7 baseline behavior + dormant merge), dir_merge=0.

## REPRODUCED on baseline: cc_blockdir_probe 25 50 → durable loss (iter14: 196/200 md5 96/100; second run iter4: 199/99). Both pureLUN(drop_caches+LUN reread) AND direx(touch→dir-EX handoff→reread) FAIL to recover → entry GONE on disk.

## REFUTATION 1 — READ-SIDE STALENESS RULED OUT: set fua_disable=0 (FUA reads pierce SCST cache) on both nodes at runtime (param is 0644). Probe STILL lost at iter4 (199/99), even faster. So the durable loss is NOT a stale plain cold-read (sess96 theory). FUA vs plain read makes no difference → the entry is genuinely absent on the LUN. The bug is WRITE-SIDE.

## REFUTATION 2 — RELEASE PATH DOES NOT ESCAPE: on the failing iter (dmesg cleared at iter start = isolated), NONE of the always-on release-escape detectors fired: no P35F-STALE-RETRY-EXHAUSTED, no P-SF-DURABLE-FAIL, no P97-RELFENCE-WEDGE, no P-DIRREL-DIFFERS, no shutdown/corrupt. The release path (xfs_mxfs_dlm.c ~3980-4375: drain-until-data_durable + flush→stale-loop publish-and-discard) completes its durability+stale checks CLEANLY. So the lost block was written DURABLE-but-STALE — it passes release's durability checks (block IS on disk) but its CONTENT is missing the peer's entries.

## MECHANISM (confirmed, refines [[sess17-CONFIRMED-staleflush-clobber-P17]]): a node durably writes an in-core dir block missing the peer's committed entries, because the ACQUIRE-side keep-guard (mxfs_dir_evict_data_blocks ~2044: undurable = in_ail && !incarn_aba && undestaged) PRESERVES an undestaged block (our committed-but-unwritten logged entries) that never adopted the peer's entries. Can't drop it (loses logged local work → sess33 CORRUPT_INCORE if XBF_DONE cleared on dirty buf); can't write it (clobbers peer). => block-level dirent UNION-MERGE is required. P62-RELOAD-FORK-SHRINK also showed shortform↔block format divergence at adjacent gens (test2 incore block gen433 vs disk shortform gen434) — the sf→block transition window is part of it.

## VIABLE FIX PATH (only one left): fold the union-merge into the CREATE's own transaction + already-held dir-EX grant. Merge v1 (per-entry fresh txn+ilock) and v2 (single-tenure xfs_trans_roll, ONE ilock at pre-lock 1305) BOTH shut down via DLM acquire TIMEOUT on the hot dir inode [[sess18-merge-v2-single-tenure-REFUTED-dlm-timeout]] — ANY extra dir-EX acquire is fatal (mxfs_dlm_ilock_begin force-shutdown on rc!=0). At xfs_inode.c:1374 (mxfs_dlm_dir_modify_refresh) the create already holds dp ILOCK_EXCL (grant cached EX) + tp active (dp not yet ijoin'd). PLAN: (1) at trans_alloc ~1313 bump resblks by K*XFS_DIRENTER_SPACE_RES headroom when multinode+block-dir+gen-advanced; (2) at 1374 ijoin dp to the create's tp, snapshot peer's durable dir blocks (mxfs_dir_merge_peer_blocks Phase1 logic — plain/FUA read all DATA blocks), xfs_dir_lookup+xfs_dir_createname the ≤K missing entries into the create's tp (NO new ilock, NO new trans, NO trans_roll — can't roll the create's tp). RISK: a createname ENOSPC dirties the create's tp → its later cancel = shutdown; bound merged entries to K (headroom) and on any createname err STOP merging cleanly before dirtying further. Validate: cc_blockdir_probe clean >25 iters AND ./run.sh 2 tcp 16/16 x>=5 consecutive, watch cache_coherency/zsl/rename regressions.

## STATE: cluster RECOVERED + HEALTHY (virsh destroy+start both, fresh prep) on B0C5862 dir_merge=0 fua_disable=1 (baseline). Marker NOT written (durable loss confirmed live). [[sess17-merge-impl-approach-and-txn-blocker]] [[sess17-reliability-data-and-marker-decision]]
