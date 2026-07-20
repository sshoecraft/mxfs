# P15-INSTR Analysis — v0.3.18 CAW slot exhaustion on AG=1

**Status**: v0.3.18 = v0.3.17 + P15-INSTR (per-iteration AG-only CAW traffic logging in `mxfs_dlm_caw_lock`). Diagnostic-only. Strip before merge.

## What we are looking for
At session-13 run-2 iter-3, T1 hit `dlm_caw: lock exhausted 100 retries for ino=0 type=3` on AG=1 (-ETIMEDOUT). T2 simultaneously hit `DLM inode lock unrecoverable: ino=128 mode=3 rc=-110` after 3×120s timeouts and force-shutdown. T1's bast_process for ino=128 was stuck in DEMOTING state because it couldn't acquire AG=1 (writeback path during drain).

This blocks reaching session-12's iter-4 AG btree corruption (we never get past iter-3).

## Hypothesized chain (from p14-analysis.md, NOT yet validated)
1. T1's bast_process for ino=128 enters DEMOTING.
2. bast_process drain triggers writeback → block allocation → mxfs_ag_dlm_lock(AG=1) fresh-acquire.
3. find_slot or CAS retries spin and exhaust at 100 retries → ETIMEDOUT.
4. bast_process can't complete; ino=128 stays DEMOTING forever.
5. T2 keeps polling for grant on ino=128; never gets it.
6. T2 times out 3×120s → unrecoverable shutdown.
7. After T2 shutdown, T2's heartbeat stops → eventually lease-expire on T1 → CAW purge of T2's slot bits → modifies AG=1 slot → T1's CAS continues to miscompare.

P15-INSTR is designed to identify which branch the 100 retries take and what slot state changes between iterations.

## Site — what was added
`xfs_dlm_caw_lock` retry loop (dlm/dlm_caw.c). Gated on `resource->type == MXFS_LTYPE_AG`.

Per iteration:
- **caw-iter** line at top of loop — find_slot result, slot_idx, gen, granted_mode, holders_{ex,pw,pr}, waiters, waiter_mode, yield_to, yield_set_ms.
- **caw-act** line per branch taken — claim-empty / already-held / already-held-higher / yield-backoff / yield-stale-clear / compat-add / upgrade-release / register-waiter / wait-for-grant-done — including CAS rc.

## What to look for in dmesg
Expected normal acquire: 1 caw-iter + 1 caw-act → done. < 5 entries per AG lock cycle.

Smoking guns:
- **100 caw-iter lines for AG=1 with same gen but changing holders/waiters** → peer is racing legitimately; we keep losing CAS or slot state changes mid-decision.
- **100 caw-iter with same generation+holders+waiters but cas_rc=-EAGAIN every time** → CAS ABA bug or compare buffer mismatch.
- **caw-iter shows yield_to=peer_bit set with growing yield_set_ms** → yield-backoff branch firing forever even though peer never acquires.
- **find=rc-2 (ENOENT) repeatedly** → slot keeps getting purged from under us (lease-expire purge race?).
- **action=register-waiter then wait-for-grant-done rc=-2 (ENOENT)** → waiter-registration CAW raced with peer's release that nuked the slot.

## Cross-merge procedure
1. Reproduce: `/tmp/mxfs_stress_v033.sh 15 512` from clyde.
2. After T1 hits "lock exhausted" or T2 hits "unrecoverable", capture both nodes' dmesg with `--color=never -T` to /tmp/t1.log /tmp/t2.log.
3. Convert `[real]` ns → unified ms, sort merged by realns.
4. Find the first P15-INSTR caw-iter ag=1 retry=0 on T1 in the failure window.
5. Walk forward 100 iterations and characterize: are CAS misses stable (same gen) or does gen advance? Is yield_to involved? Does find_slot ever return ENOENT?
6. Walk T2's events in same window — what is T2 doing to AG=1 (acquire/release/lease-expire purge)?

## Files modified for v0.3.18
- `dlm/dlm_caw.c` — P15-INSTR pr_warn calls in mxfs_dlm_caw_lock retry loop
- `VERSION` 0.3.17 → 0.3.18

## Notes
- P9/P10/P13/P14/MX/P6/P15-INSTR all in tree — strip ALL only after open bugs closed.
- `mxfs_dlm_reset_inode_for_create` helper in xfs_mxfs_dlm.c still unused.
- If P15 confirms lease-expire-purge race: fix is to gate purge on the resource being unheld locally + bump generation visibly so in-flight CAS bails cleanly.

## v0.3.18 stress run 1 (2026-04-28) — iter-1 FAIL, dir-stale Mode A
Re-confirmed dir-stale-on-disk Mode A bug from session-13 run-1 / p14-analysis.md priority #3.

Trace (cross-merged from /tmp/p15_t1.log + /tmp/p15_t2.log):
- T2 04:35:01 holds ino=128 EX, BAST received (deferred — active holders).
- T2 dialloc PICK ino=131 in dir=128 (xfs_create perf_t2 still running).
- T2 trans commits, ilock_end fires bast_process: BAST set stale → REL-INLINE-PRE/POST (~0.65 ms for the CAW unlock alone; full bast_process duration not bracketed by P13).
- T2 releases ino=128 DLM grant.
- T1 04:35:01 GRANT-WAIT-START → ACQ-FRESH ino=128 → DLM reload `disk_size=6 disk_mode=0x41ed disk_nlink=2` (EMPTY DIR — perf_t2 not present on disk).
- T2 04:35:05 re-acquires ino=128 EX for the rm. P6-INSTR shows `mem_entries=1 first_entry="perf_t2" mem_size=21` — in-memory dir HAS perf_t2.
- T2 reload reads `disk_size=6` AGAIN — pulls empty disk content over correct in-memory state.
- T2 xfs_dir_removename rc=-2; xfs_remove had dirtied trans → xfs_trans_cancel → Corruption(0x8) → shutdown.

Key observation: bast_process at xfs/xfs_mxfs_dlm.c:121-123 already calls
  xfs_log_force(SYNC) + xfs_ail_push_all_sync(mp->m_ail) + blkdev_issue_flush
BEFORE staling the cluster buf and releasing the DLM grant. Yet the on-disk
inode at /dev/sda doesn't reflect T2's in-memory `size=21`. Hypothesis families:
  (a) Cluster-buf write was issued and acknowledged, but qemu/LIO holds it in
      a host-side cache and T1's read sees pre-write content. blkdev_issue_flush
      should defeat this — verify by tcpdump on the SCSI channel or by adding a
      direct read-back validation in bast_process before unlock.
  (b) xfs_iflush PACKED stale state. The data fork was modified in-memory by
      xfs_dir2_sf_addname but xfs_iflush_int may not have seen the latest
      i_df.if_data when AIL push ran. Less likely — XFS inode locking should
      serialize this.
  (c) The cluster buf was stale-marked locally before AIL push fully committed
      the iflush write. Order in bast_process is push then stale, but reads
      after stale go to disk regardless.

P15-INSTR did NOT fire visibly during this failure window because the failure
is per-inode coherence, not AG CAW. P15-INSTR remains armed for the CAW
exhaustion bug, but iter-1 dir-stale needs to be resolved (or made rarer)
before we can reproduce it.

Decision: retry stress to see if iter-1 sometimes passes (matches session-13
history); if persistently failing, fix dir-stale before continuing CAW work.

## v0.3.18 stress run 2 (2026-04-28) — iter-1 FAIL, AG btree corruption (priority-2 bug)
Different failure than run-1, same iter-1. This IS the session-12 family
P14-INSTR was designed to investigate, but with a TWIST.

Failure: T1 04:39:47, `xfs_alloc.c:2106 ltbno+ltlen > bno` (left-neighbor
overlaps bno being freed) in `xfs_free_ag_extent → __xfs_free_extent →
xfs_extent_free_finish_item → xfs_defer_finish → xfs_bunmapi_range →
xfs_itruncate_extents_flags → xfs_free_eofblocks → xfs_file_release →
__fput_sync → __x64_sys_close`. **Comm: dd.**

So this is NOT the explicit `rm /mnt/shared/perf_t1` — it's XFS's
speculative-EOF-blocks free during dd's close(2). dd had just finished
writing 512MB; on close, xfs_free_eofblocks frees the speculative
preallocation past file end. That free hits bnobt left-neighbor overlap.

Critical observation: T1 was the SOLE acquirer of AG=1 in this run.
- P15-INSTR shows T1 acquired AG=1 at 04:39:42 (fresh, claim-empty, slot=33966).
- T2 never touched AG=1 (verified: no `agno=1` events in t2.log).
- P14-INSTR shows AG=1 fresh acquire was clean: finobt+agi+agf all STALED
  successfully at 04:39:42, no SKIP verdicts.
- No further AG=1 acquires by anyone until corruption.
- 5 seconds of T1-exclusive AG=1 ownership → bnobt corrupted itself.

This RULES OUT the H1-style "stale buffer survives stale" hypothesis for
this specific failure. The bnobt corruption is single-writer, single-AG,
no peer interference. So either:
  (X) MXFS's wrapping of XFS's bnobt update path corrupts state during
      single-writer operation. Possible interactions: I/O completion
      iodone callback ordering, bli list manipulation in mxfs_dlm hooks,
      buffer reference counting differences from stock XFS.
  (Y) Speculative-EOF allocation interacts badly with MXFS — e.g.
      MXFS releases a buffer mid-allocation, AIL pushes a partial
      bnobt update to disk, T1 re-reads bnobt later in stale state.
      But T1 didn't re-acquire AG=1 in this window.
  (Z) An independent XFS bug exposed by changed timing.

This is a different signature than session-12 (`bno+len > gtbno` at line 2140
during regular free). Session-12 was right-neighbor; run-2 is left-neighbor.
Both are same family (`xfs_free_ag_extent` boundary check).

Files for cross-merge: /tmp/p15_run2_t1.log + /tmp/p15_run2_t2.log

## Cross-cutting observation: P14+P15-INSTR timing pressure
v0.3.16 hit CAW exhaustion at session-13 iter-3 (run-2). v0.3.17 added
P14-INSTR and shifted iter-1 outcome toward dir-stale Mode A or AGI-SKIP.
v0.3.18 added P15-INSTR (more pr_warns in CAW path) and now BOTH iter-1
runs fail differently:
  - run-1: dir-stale Mode A
  - run-2: bnobt left-neighbor corruption during EOF blocks free

The accumulated pr_warn cost in BAST/CAW critical paths is changing the
race window. For comparison, session-12 (v0.3.16, no P14/P15) had iter 1-3
PASS clean before iter-4 hit AG btree corruption. Now we cannot get past
iter-1 with P14+P15 in tree.

Implication: the diagnostic load is non-trivial. Eventual cleanup must strip
ALL of P9/P10/P13/P14/MX/P6/P15-INSTR before any final benchmarking. The
diagnostics are themselves a perturbation.

## Status at end of v0.3.18 work (2026-04-28)
- P15-INSTR built, deployed, validated (smoke test + 2 stress runs).
- 0 instances of CAW exhaustion captured (priority-1 bug not reached).
- 1 instance dir-stale Mode A captured with full trace (priority-3).
- 1 instance bnobt left-neighbor corruption captured with full trace (priority-2).
- Both bugs reproduce iter-1 reliably with v0.3.18 in tree.
- Conclusion: priority-1 work is BLOCKED by priority-2/3 reproducing earlier
  than they did in session 13. Next session should fix one of the iter-1
  bugs (preferably priority-2 AG btree, or strip P15 to reduce timing
  pressure first) before retrying CAW investigation.

## v0.3.18 stress run 3 (2026-04-28) — iter-4 FAIL, RELIABLE bnobt corruption repro
Reset both VMs (virsh destroy/start), fresh mkfs, parallel-dd 5-iter workload.
iters 1-3 PASS clean, iter 4 FAIL: T1 bnobt left-neighbor corruption
(`xfs_alloc.c:2106 ltbno+ltlen > bno`) — same signature as run-2.

**Single-node (T2 mxfs unloaded) repro: 10/10 PASS clean.**
**T2 mounted+idle repro: 10/10 PASS clean.**
**Multi-node parallel-dd: iter-4 FAIL.**
Bug requires T2 actively writing to MXFS (which causes AG ping-pong with T1).

**Different stack from run-2** but same corruption:
- run-2: dd close() → xfs_file_release → xfs_free_eofblocks (foreground)
- run-3: kworker xfs-inodegc → xfs_inactive → xfs_inactive_truncate (bg)
- Both reach: xfs_itruncate_extents_flags → xfs_bunmapi_range → ... →
  xfs_free_ag_extent → bnobt left-neighbor check fail.

**Run-2 conclusion REVISED**: my "T2 never touched AG=1" claim was wrong.
Run-2's t2.log was filtered for `agno=1|AG=1` patterns but P15-INSTR uses
`ag=1` format. Run-3 cross-merge shows T2 heavily uses AG=1 (ACQ-FRESH +
REL-INLINE alternating with T1 every 1-3 seconds, ~6 times each direction
over 5 iters).

**P14-INSTR AG=1 verdicts in run-3**: ALL bnobt/cntbt/agf/agfl verdicts on
BOTH T1 and T2 fresh-acquires are STALED clean (no SKIP-* of any kind on
AG=1 buffers). AGI buffers SKIP-bli-unlocked occasionally (4 instances) but
on AG=0 not AG=1, so not the cause of THIS corruption.

**P15-INSTR for AG=1 slot=25410** generation history:
- gen=1 (T2 first), 4 (T1), 7 (T2), 10 (T1), 13 (T2), 16 (T1), 19 (T2), 22 (T1)
- Then RESET to 1 at 12:23:58: T1's `wait-for-grant-done rc=-2` (slot wiped
  while waiting), T1 retries, claim-empty re-creates slot at gen=1, T1 acquires.
- Corruption fires ~8 seconds later in inodegc worker.

**Hypothesis SHARPENED**: Bug is AG-meta coherency under heavy ping-pong,
NOT single-writer. xfs_buf_stale + xfs_buf_find_lock SHOULD force re-read
from disk (find_lock at xfs_buf.c:434 does `bp->b_flags &= _XBF_KMEM`
clearing XBF_DONE). So:
  (i) Peer's bnobt mod never reached disk (write didn't complete despite
      log_force + ail_push + blkdev_flush in bast_work_fn).
  (ii) Local stale-then-reread races with concurrent ACQ-FRESH.
  (iii) Different buf instance / different daddr key in cache vs in use.

**Site B / new diagnostic added**: P14-INSTR Site B at xfs_alloc.c:2141
logs only the RIGHT-neighbor failure (bno+len > gtbno). The LEFT-neighbor
ltbno-failure at line 2106 had NO diagnostic. Added mirror dump
(`P15-INSTR FREE-AG-EXTENT-FAIL-LEFT`) with bno, len, ltbno, ltlen,
agf_freeblks (on-disk via agbp->b_addr), agf_longest, pagf_freeblks
(in-memory cached), pagf_longest. Discrepancy between on-disk and in-memory
counters distinguishes (i) vs (iii).

Rebuilt and ready to redeploy. Run-4 stress will capture the actual
extent values.

## v0.3.18 + LEFT-FAIL diagnostic — run 4 (2026-04-28) ROOT CAUSE FOUND

iter-4 FAIL on T2. `xfs_free_eofblocks` during dd close().
P15-INSTR FREE-AG-EXTENT-FAIL-LEFT captured:
```
agno=0 bno=133896 len=5360 ltbno=5400 ltlen=256734
agf_freeblks=256741 agf_longest=256734 pagf_freeblks=256741 pagf_longest=256734
```

bno=133896..139256 (free request) is fully covered by ltbno=5400..262134
(existing free extent). agf_freeblks (on-disk) == pagf_freeblks (in-memory).
**Disk and memory AGREE — both think 133896-139256 is already free.** That
rules out "write didn't reach disk" hypothesis. The extent was
double-allocated (T1's alloc AND T2's alloc both got the same physical
range), one node's allocation made it into bnobt and the other didn't, and
the second node's free finds the bnobt sees the range as free.

### Root cause

`xfs_alloc_vextent_finish` at libxfs/xfs_alloc.c:3704 calls
`mxfs_ag_dlm_unlock(args->mp, args->pag)` IMMEDIATELY after
`xfs_alloc_update_counters` — but BEFORE the transaction containing the
allocation commits.

The XFS comment at lines 3636-3650 in xfs_alloc.c explicitly notes:
> "We can't release the AGF until the transaction is commited, so at this
> point we must update the 'first allocation' tracker..."

The agbp xfs_buf_lock IS held until trans commit (standard XFS) — that
keeps another local thread out of the AGF. But the MXFS DLM AG lock —
the ONLY thing serializing peer access to AG metadata — is released
right after this.

### Race
1. T1: mxfs_ag_dlm_lock(AG=0). Allocator dirties bnobt buffer (buf log
   item attached). Trans NOT YET committed.
2. T1: alloc_vextent_finish → mxfs_ag_dlm_unlock. pag_dlm_holders=0,
   pag_dlm_cached=true.
3. T2: BAST sent (T2 wants AG=0 for its own alloc).
4. T1: bast_work_fn fires.
   - xfs_log_force(SYNC): drains CIL → log → AIL.
   - **But T1's alloc trans isn't in CIL yet (not committed) — log_force
     can't sync what hasn't been committed.**
   - xfs_ail_push_all_sync: pushes whatever's in AIL.
   - blkdev_issue_flush.
   - mxfs_v5_dlm_ag_unlock — DLM grant released.
5. T2: ACQ-FRESH AG=0. invalidate_ag_meta STALEs T2's bnobt buf clean.
6. T2: reads bnobt from disk → sees PRE-T1-allocation state →
   133896-139256 still free → allocates same range to perf_t2.
7. T1's trans eventually commits → bnobt mod hits disk via AIL push →
   on-disk bnobt now reflects T1's allocation, overwriting whatever T2
   saw at step 6. (T2's bnobt mod also competes; one wins.)
8. T2: rm perf_t2 → xfs_free_eofblocks of 133896-139256 → finds left
   neighbor 5400-262134 already free → corruption.

This is the same family as priority-1 CAW exhaustion (timing-dependent
multinode race) but a distinct mechanism. P15-INSTR's LEFT-FAIL diagnostic
nailed it.

### Fix design (NEXT SESSION — do NOT implement late-night)

Three approaches, ranked:

(A) **Tie DLM unlock to buf-log-item commit** (most XFS-native): make
mxfs_ag_dlm_unlock at vextent_finish a NO-OP with a flag; register a
commit-time callback (xfs_buf_iodone or buf_log_item commit hook) that
fires the actual mxfs_ag_dlm_unlock when the agbp's modifications iflush
to disk. This aligns DLM lifetime with the agbp buf lock lifetime, which
is the XFS-comment-mandated invariant. Most invasive but most correct.

(B) **Per-AG transaction counter** (operationally simple): increment on
mxfs_ag_dlm_lock acquire-from-trans; decrement on trans commit (via
xfs_trans_commit hook). bast_work_fn waits for counter==0 before
flush+release. Less invasive but introduces global counter contention
and requires a hook into xfs_trans_commit.

(C) **bast_work_fn calls xlog_cil_force** (simplest patch, may not be
sufficient): xlog_cil_force forces the CIL queue to drain into the log
even for not-yet-committed transactions. But trans that haven't called
trans_commit yet aren't IN the CIL — so this only helps for the
"committed but not yet pushed" subset of races, not the "alloc done,
trans still active" case here. Likely insufficient.

Recommend (A). Do design + implementation in next session with fresh
context. Estimate 100-200 lines + 1 test cycle to validate.

### Status at session 14 end
- Priority-2 bug ROOT-CAUSED. P15-INSTR LEFT-FAIL diagnostic captured the
  smoking gun in run-4.
- Priority-1 (CAW exhaustion) still unreached — but priority-2 fix should
  let stress run further, possibly into iter-3+ where CAW exhaustion fires.
- Priority-3 (dir-stale Mode A) likely the SAME ROOT CAUSE: per-inode
  DLM unlock fires before trans commit, peer reads stale dir on next
  acquire. The "0.65ms REL-INLINE" timing in run-1 fits — REL-INLINE
  fires inside ilock_end which is called from xfs_iunlock which fires
  while the trans containing the dir modification may not be committed
  yet. SAME fix pattern as (A) likely closes both.

Files captured: /tmp/p15_run4_t1.log, /tmp/p15_run4_t2.log,
/tmp/p15_run3_t1.log, /tmp/p15_run3_t2.log.
