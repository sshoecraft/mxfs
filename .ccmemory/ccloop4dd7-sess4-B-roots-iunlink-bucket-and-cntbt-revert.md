---
name: ccloop4dd7-sess4-B-roots-iunlink-bucket-and-cntbt-revert
description: sess4 roots #2/#3 FIXED: b59r1 iunlink-remove empty-bucket on adopted mirror (v0.11.60 gate widened); b60r2 pinned-cntbt DMA revert (v0.11.61 P110 un…
metadata:
  type: project
tags: [ccloop-4dd7, root-cause, iunlink, cntbt, read-over-logged]
---

# ccloop-4dd7 sess4 roots #2 and #3 (both RULE-4 proven from live round logs)

## Root #2 — b59r1: iunlink-remove empty-bucket on adopted mirror (FIXED v0.11.60 = E412B1D7)
- Signature: `xfs_ifree returned error -117` → `Metadata I/O Error at xfs_inactive_ifree` (xfs_inode.c:3189) on test2.
- Chain: test2's own rm freed ino 136 (P150-FREE-IBT agno=0 off=8, freecount 52→53) at 16:50:49.2425;
  11ms later a stat's lookup_fast → d_invalidate → evict ran SYNC inactivation of a RE-IGOT mirror of 136
  that adopted nlink=0 + live mode from the not-yet-destaged dinode (P71-INSTR: disk_dimode=0100644
  disk_dnlink=0, bucket-8 head=NULLAGINO both in-core+disk). xfs_ifree → xfs_iunlink_remove walked the
  EMPTY bucket → P71 agi-unlinked-garbage → -117 (non-ESTALE, so the sess3 difree-ESTALE backstop never
  reached — iunlink_remove runs BEFORE difree).
- Existing guard (sess2 second arm, xfs_inode.c ~3096) checked bucket-empty BUT was gated on
  xfs_inode_on_unlinked_list(ip) — always FALSE for adopted mirrors (prev=0/next=NULLAGINO adopted from
  dinode; sess3 documented this exact hole).
- FIX: dropped the on_unlinked_list condition — bucket-empty check runs for EVERY multinode ifree.
  Justification: an empty bucket at ifree time for an nlink=0 inode always means the unlink entry was
  consumed by the completed free; every legitimately-unlinked inode stays bucket-reachable until exactly
  one ifree removes it. Tx still clean at the check → IFREE-REVALIDATE-SKIP epilogue (error=0).

## Root #3 — b60r2: pinned-cntbt plain-bio DMA revert (FIXED v0.11.61 = 36C906B6)
- Signature: `Internal error i != 1` xfs_alloc.c:677 (xfs_alloc_fixup_trees) + :2695 (xfs_free_ag_extent)
  → defer_finish dirty-cancel shutdown (test2, comm=bash mid xfs_bmap_btalloc near-alloc).
- Chain: `P110-BIO-OVER-LOGGED daddr=16 ops=xfs_cntbt pin=1 has_bli=1 comm=bash` fired ~500µs before, in
  the SAME task: a plain-bio READ DMA'd the platter AG0 cntbt over PINNED (in-CIL) records; bnobt kept
  newer in-core state → bnobt/cntbt record divergence → i != 1.
- The read-side keep action had been DISABLED in sess122 (blanket LOG-ONLY) because the broad gate
  (mxfs_buf_has_uncheckpointed_mods: pinned|BLI|dirty|in-AIL|delwri) refused legit AGI-adopt reads during
  ifree (destaged lingering-BLI case) and regressed cache_coherency.
- FIX: re-enabled the keep gated on mxfs_buf_is_undestaged(bp) (pinned || li_lsn > payload-LSN stamp) —
  refuses DMA + completes read in-place (XBF_DONE + ioend, mirrors the active sess61 bmbt guard at
  ~8436) ONLY for genuinely committed-unwritten AG-meta; destaged-lingering stays LOG-ONLY/read-proceeds
  (sess122 case preserved). pal/linux/xfs_buf.c ~8395.

## Also in sess4 so far
- Root #1: owner-evict mid-tenure kill (v0.11.58) — see ccloop4dd7-sess4-A memory.
- v0.11.59 instrument: i_dlm_exh_pid/comm/since stamps at all 9 ex_holders++ sites + P36-EXH-STACK holder
  stack dump at MHT-REARM strikes 200/5000n (mxfs_pal_dump_task_stack added to PAL). For the OPEN b58r1
  184s blocked-holder stall (task #6) — holders were live rm threads blocked at an invisible (non-DLM)
  wait site, suspect log-space; instrument will name it on next occurrence.
- difree-ESTALE fix VERIFIED live (b57r3): P-DIFREE-DBL agino=134 → clean skip, freecount consistent.
- Ladder: b57r1-4 clean; b57r5=root#1; b58r1=stall; b59r1=root#2; b60r1 CLEAN; b60r2=root#3.
  Ladder resets at b61r1 on v0.11.61. LOGDIR=tests/logs/vmrig_dialloc_20260724_130107Z.
- Host clyde rebooted by user 10:43 (LIO rebuilt, VMs restarted; /tmp wiped).
