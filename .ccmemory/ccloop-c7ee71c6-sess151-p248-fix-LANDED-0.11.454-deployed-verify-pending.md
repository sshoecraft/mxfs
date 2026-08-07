---
name: ccloop-c7ee71c6-sess151-p248-fix-LANDED-0.11.454-deployed-verify-pending
description: sess151: D-RELEASEALL-LREQ-RETIRE-MISSING fix (A) + stuck-notify wiring (B) LANDED on 0.11.454, DEPLOYED to 32/caw. Verify run #2 + census PENDING.
metadata:
  type: project
tags: [mxfs, sess151, P248, release_all, lreq, stuck-notify, 0.11.454, deployed]
---

# sess151 — P248 fix + stuck-notify LANDED and DEPLOYED; verification run pending

## What landed (builds clean, srcversion 80380189DB5175E6A8CF74E, VERSION 0.11.454)

### Change A — D-RELEASEALL-LREQ-RETIRE-MISSING (per sess150 GPT ruling, exactly)
- `lreq_pub_seq_peek(ctx,res)` added after `lreq_release_all` (~dlm_caw.c:4976): bare peek
  under lreq_lock (no clr_begin — ruled shape for the quiesced unmount path); 0 = no-entry
  anchor (only bump is lreq_finish's e->pub_seq++ at ~4614, so published entries read >=1).
- `caw_release_all_body` per-slot loop: locals pub_seq0/seq_sampled/seq_churned/seq_res;
  sample ONCE at first known identity (right after `res_known = true`, BEFORE first CAS);
  memcmp identity churn across retries → seq_churned (decline retire, fail-closed).
- After `untrack_held`: `if (cleared && res_known && !seq_churned) lreq_release_all(ctx,&res,pub_seq0);`
  — mirrors single-unlock order at ~8407 (untrack-then-retire; tenure keeps entry non-GC in interval).
  Not-cleared-but-owed does NOT retire (obligation keeps the entry).
- P248 identity dump in destroy loop: first 8 leaked entries print
  `P248-LREQ-LEAK-ENT type/id/tenure=NL/CR/CW/PR/PW/EX/pub_seq/attempts/writers/pin/clr_active/owed_pend/busy/oq`.
  MXFS_LOCK_MODE_COUNT=6 (include/mxfs/mxfs_dlm.h:35); fixed-field print, no scnprintf needed.

### Change B — stuck-notify chain (SHUTDOWN_META_IO_ERROR)
- xfs_mount.h: `struct work_struct m_mxfs_dlm_stuck_work` next to foreign_replay_work.
- xfs_mxfs_dlm.c: `mxfs_dlm_stuck_work_fn` (xfs_alert + xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR)),
  `mxfs_dlm_stuck_notify` (queue-only: queue_work(system_unbound_wq,...)), registered in
  mxfs_dlm_cache_init via existing `mxfs_v5_dlm_set_dlm_stuck_notify` (sess132 v5 forwarding
  already existed; only the XFS half was missing).
- pal/linux/xfs_super.c: `cancel_work_sync(&mp->m_mxfs_dlm_stuck_work)` added right after the
  foreign_replay cancel at BOTH post-cache_init teardown sites (unmount block ~1574 and
  out_unmount ~3179). out_filestream_unmount deliberately untouched (pre-cache_init, work not INIT'd —
  same as foreign_replay). Ordering per ruling: v5 shutdown first (worker join + channel close
  under lreq_lock in stop(); CAW ctx protected by unsafe_to_free leak-don't-free), then cancel.

## Deployment state (RIGHT NOW)
- Run #1 `./run.sh 32 caw prep_cluster` DONE (73s, budget 300s): all 32 mounted on
  80380189DB5175E6A8CF74E, converged active_count=32. That run's TEARDOWN was on the OLD
  0.11.453 build (its P248 hits are in the baseline below, expected).
- Baseline census (post-run-1): p248ent=0 on ALL 32 (new probe, no new-build teardown yet);
  cumulative p248 history: test1=4, test18/19/20/22=6, rest=7. NOTE `grep -c P248-LREQ-LEAK`
  substring-matches -ENT lines too — count both separately when computing the delta.

## NEXT (the verification — task #3, in_progress)
1. Run #2 `./run.sh 32 caw prep_cluster` (300s timeout): its teardown runs ON 0.11.454 —
   this is the measurement.
2. Census delta vs baseline above: new P248-LREQ-LEAK aggregate lines MUST be 0 and
   P248-LREQ-LEAK-ENT MUST be 0 on all 32; `released heartbeat slot N (clean teardown)` present
   32/32; P253/P255/P257/P258/P259/P260/P261/P262 deltas zero (sess150 criteria).
   P248-LREQ-REL-KEPT would also be new signal (retire declined — investigate if nonzero).
3. If clean: D-RELEASEALL-LREQ-RETIRE-MISSING → FIXED AND VERIFIED in OPEN_DEFECTS.json
   (edit via python3, see sess150 transcript for the JSON shape), 28 open remain.
4. Then task #4: compile-memories (COMPACTION DUE, ~191 unfolded, keeps growing).
5. Then the ledger front-runner: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY step 1
   (369 knob=1 full board + knob=0 regression board) or per state-hook order.

## Also
- Task list did not survive the relay (recreated as #1-#4 this session; #1/#2 completed).
- Tools build stamped 0.11.454 (mkfs/chk/resize standalone C — don't link dlm_caw.c).
- No new compile warnings at any edit site (pre-existing -Wmissing-prototypes noise only).
