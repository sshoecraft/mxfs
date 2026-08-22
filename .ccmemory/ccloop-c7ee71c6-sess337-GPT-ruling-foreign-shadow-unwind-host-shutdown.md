---
name: ccloop-c7ee71c6-sess337-GPT-ruling-foreign-shadow-unwind-host-shutdown
description: sess337 NEW DEFECT + RULE-5 ruling: foreign-replay mid-replay failure shuts down REPLAYER's live mount (xlog_do_recovery_pass:4359); fix = xfs_buf_de…
metadata:
  type: project
tags: [d-513, foreign-replay, shutdown, rule-5, stop-ship]
---

# sess337 — foreign-shadow unwind host-shutdown defect + GPT fix ruling

## Defect (PROVEN, 32/caw rig, 0.12.4 sv B04D26F33C9CB068166732F)
Genuine shape-4 run (`TORN_ITEMS=3 VICTIM_LOAD=20 VICTIM_LOAD_MODE=inode tests/d513_refusal_containment.sh 32 test6 4`):
P227-FR-FORCED-TORN fired at an XFS_LI_INODE item (0x123b) with a real 2-item applied prefix; 13us later the ELECTED REPLAYER's (test1) OWN live fs shut down: "Filesystem has been shut down due to log error (0x2)". Verdict still published TORN/FSWIDE seq=1, 31/31 imported, but the replayer fs is dead = survivor suicide, the exact class D-513 forbids. Production-reachable: any NATURAL torn foreign slice with >=1 applied item (buffer_list non-empty) hits it.

## Root (direct evidence, exact site)
`xlog_do_recovery_pass` xfs_log_recover.c:4359: on pass-2 error with non-empty buffer_list it calls `xlog_force_shutdown(log, SHUTDOWN_LOG_IO_ERROR)` so the following `xfs_buf_delwri_submit` stales the partial-checkpoint buffers without IO. But `log` is the SHADOW xlog and `xlog_force_shutdown` does `xfs_set_shutdown(log->l_mp)` (xfs_log.c:3888) — the shadow's l_mp is the survivor's LIVE mount. The stale-discard is keyed off MOUNT shutdown in `__xfs_buf_submit` → `xfs_buf_ioend_fail`.

## GPT RULE-5 ruling (fix shape = option b as buffer-layer op)
1. Add `xfs_buf_delwri_fail(buffer_list, error, origin)` in pal/linux/xfs_buf.c: for each queued bp — remove from b_list, clear _XBF_DELWRI_Q once, set b_error, stale, run the NORMAL failure completion (same machinery as xfs_buf_ioend_fail: _XBF_LOGRECOVERY cleanup at xfs_buf.c:2246, b_iodone, refs) with NO device IO and NEVER consulting/modifying b_mount shutdown. Do NOT open-code in log_recover (option a rejected); do NOT use a persistent b_flags bit; xfs_buf_delwri_cancel (xfs_buf.c:11110) must NOT be assumed suitable (may skip recovery iodone).
2. In xlog_do_recovery_pass error arm: `if (error && xlog_is_mxfs_untrusted_replay(log)) error2 = xfs_buf_delwri_fail(...)` else keep upstream shutdown+submit. Preserve primary error.
3. CRITICAL: inspect everything reached via b_iodone — callbacks may themselves call xfs_force_shutdown(bp->b_mount). Provenance must distinguish foreign-shadow recovery IO from live metadata IO; do not infer from b_mount.
4. AUDIT scope: all xlog_force_shutdown/xfs_force_shutdown/xfs_set_shutdown reachable from xlog_recover/xlog_recover_finish/xlog_recover_cancel/item pass2 ops (other sites: log_recover.c:3591 defer-ops, 4634, 4665); real replay-buffer WRITE-ERROR path (xfs_buf_ioend → callbacks → SHUTDOWN_META_IO_ERROR on b_mount?); xlog_recover_cancel teardown must touch only shadow-owned state; foreign path must never use live CIL/AIL/m_log.
5. Verdict stays TORN+FSWIDE. Ordering before durable publish: stop submissions → no-IO-complete current batch → drain previously submitted replay IO (mid-pass delwri_submit is synchronous, so naturally drained — verify) → cancel shadow → publish → import. Optional conservative fields (PARTIAL_REPLAY_POSSIBLE etc.) — do not claim rollback.
6. LEDGER: separate linked defect entry (not folded into #90). Closure criteria: shape-4 zero host shutdowns; natural torn + applied prefix same; batch buffers no IO + recovery state cleared; drain before publish; injected replay-write IO error doesn't kill survivor; live-mount IO error still shuts down normally; cancel leaves nothing; all survivors incl. replayer import same verdict.

## Also this session (rig results, 0.12.4)
- Churn-load run = NATURAL incident-513 refusal (both txns ATOMIC-SKIP'd, refused=2 rc=-117, WOULD_APPLY=10/all_apply=2 = sess320 discrepancy) → containment PASS: 1 refuser, AG-MASK publish, 31/31 import, 0 shutdowns. Satisfies sess328 Q2(a).
- Key insight: ONLY XFS_LI_INODE items genuinely apply on foreign replay (taint scan log_recover.c:2927 flags any BUF/DQUOT/QUOTAOFF/ICREATE txn); shape-4 countdown (log_recover.c:3051) needs pure-inode victim load. Driver has VICTIM_LOAD_MODE=inode (prepopulate+touch+sync) + TORN_ITEMS env.
- Fleet needs RE-PREP (durable FSWIDE quarantine from the shape-4 run on the LUN).
