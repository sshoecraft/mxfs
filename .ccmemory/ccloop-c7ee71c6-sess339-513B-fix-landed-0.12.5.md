---
name: ccloop-c7ee71c6-sess339-513B-fix-landed-0.12.5
description: sess339: #91 D-FOREIGN-SHADOW-UNWIND-HOST-SHUTDOWN-513B fix LANDED+BUILT 0.12.5 sv E9421B6AA014B2B7C2F2547 — NOT reviewed/deployed; found 6th queue f…
metadata:
  type: project
tags: [d-513, foreign-replay, shutdown, landing]
---

# sess339 — #91 (513B) implementation landed, 0.12.5

Implements the sess337 GPT ruling + sess338 audit decisions. Build clean
(`make clean && make modules`), sv E9421B6AA014B2B7C2F2547. NOT RULE-5
reviewed, NOT deployed, NOT rig-verified.

## The change set
1. `xfs/xfs_buf.h`: `bool b_mxfs_foreign_recovery` (not a b_flags bit per
   ruling) + `xfs_buf_delwri_fail(list, error)` prototype.
2. `pal/linux/xfs_buf.c`:
   - `xfs_buf_ioend_handle_error`: EARLY gate — foreign buffer → alert +
     `P227-FR-BUFFAIL` + `goto out_stale` (skips the `_XBF_LOGRECOVERY`
     one-strike shutdown and the permanent-error shutdown, both of which
     act on b_mount = the live survivor).
   - `__xfs_buf_ioend`: clears the provenance in the final flags-clear
     beside `_XBF_LOGRECOVERY` (never leaks into live IO of the cached
     buffer).
   - `xfs_bwrite`: snapshots the provenance BEFORE submit (completion
     clears it) and skips its `xfs_force_shutdown` on error for foreign.
   - `xfs_buf_delwri_fail`: delwri_submit-style walk; per buffer: lock,
     lazy `_XBF_DELWRI_Q` removal check, clear
     DELWRI_Q/ALLOC_QUEUED/ASYNC/DONE, set WRITE, `xfs_buf_ioerror(err)`
     + `xfs_buf_stale` + inline `xfs_buf_ioend`, then iowait+relse.
     No submit → no sync credit → complete()/iowait() balanced.
     bli retirement safe: `xfs_buf_item_done` already passes
     shutdown_type 0 for `_XBF_LOGRECOVERY` buffers (buf_item.c:2403),
     so the not-in-AIL delete cannot shut anything down.
3. `xfs/xfs_log_recover.c:4343` error arm: `xlog_is_mxfs_foreign_replay`
   → `P227-FR-UNWIND` + `xfs_buf_delwri_fail`; else upstream
   `xlog_force_shutdown` + submit. Adopted-slice deliberately keeps the
   shutdown (sess338 decision: its log IS the mounting fs's own; skipping
   would let mount teardown stamp a failed dirty slice clean).
4. Provenance stamped at SIX queue-site families (sess338 audit listed 5;
   sess339 code sweep found the 6th):
   - buf_item_recover: rtsb (:1103), delwri (:1142), bwrite arm (:1139)
   - inode_item_recover :622; dquot_item_recover :171
   - icreate → `xfs_ialloc_inode_init` — new `bool mxfs_foreign_recovery`
     param (2 callers)
   - **NEW 6th: swapext owner-change** `xfs_btree.c:4847`
     (XFS_ILOG_DOWNER/AOWNER on an INODE item — INODE items DO apply on
     foreign replay). Bool threaded through
     `xfs_recover_inode_owner_change` → `xfs_bmbt_change_owner` →
     `xfs_btree_change_owner` → bbcoi. Live caller (xfs_bmap_util.c
     swapext) passes false.

## Next (in order)
1. RULE-5 diff review (sess335 found 3 stop-ships, sess333 found 6 on
   this subsystem — do not skip). Include gate-deviation + 6th family.
2. Fix findings; re-prep fleet (FSWIDE quarantine on LUN from sess337);
   shape-4: `TORN_ITEMS=3 VICTIM_LOAD=20 VICTIM_LOAD_MODE=inode
   tests/d513_refusal_containment.sh 32 test6 4` → PASS = TORN/FSWIDE
   published, 31/31 import, ZERO shutdowns including replayer test1.
3. Remaining #90 items: shape-1 under load, knob-off regression board.
