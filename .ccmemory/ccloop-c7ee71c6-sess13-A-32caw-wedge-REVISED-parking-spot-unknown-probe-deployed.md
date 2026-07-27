---
name: ccloop-c7ee71c6-sess13-A-32caw-wedge-REVISED-parking-spot-unknown-probe-deployed
description: sess13: 32/caw wedge diagnosis REVISED (supersedes sess12-E cycle): bash parked 222s in UNKNOWN spot holding ILOCK; owner-stack probe deployed v0.11.…
metadata:
  type: project
tags: [32-node, wedge, rule4, rule5-gpt, instrumentation, open]
---

# sess13-A: 32/caw fence wedge — sess12-E story CORRECTED, parking spot still unknown, decisive probe deployed

## What sess12-E got wrong (proven from test14 journal -b -2, boot 11:03-11:24)
The "truncate holds ILOCK+dirty trans waiting on AG-11 in P1-AGWAIT" cycle is WRONG in its final
parking spot. Actual sequence (all monotonic secs, test14):
- 562.268 P-RELOAD-IDENTICAL: bash's `: > probe_file` (fence still-writable probe, ino 23068801,
  19B 1-extent, AG-11) did a FRESH inode-DLM EX acquire + reload.
- 562.269-.271 truncate trans: setattr_size → __xfs_bunmapi logs; P1-AGWAIT ag=11 (GENUINE peer-held)
- 562.297 P145-FREE agno=11 — the AG poll SUCCEEDED in 26ms, block freed. NOT the wedge.
- 562.299 defer roll dropped the AG (P1-AGDUP-DROP + P12-ULBP sched_now=1, peer BAST pending 132s);
  AG bast work entered (P12-WORK holders=0 cached=1)
- 562.300 P12-READOPT n=1 (bash re-acquired via cached path) + P12-ULBP readopt=1 (released again);
  last P2G = xfs_vn_update_time ILOG_TIMESTAMP.
- THEN BASH SILENT 562.300→785. During 565→784: AG-11 bast work cycles forever (bounded AIL push
  stalls on the ONE AG-11 AIL item = ino 23068801, ilocked=1 EVERY sample (rwsem_is_locked),
  in_ail=1 pin=0 ili=0x4001(CORE|TIMESTAMP) iflags=0x20000(MXFS_IF_FIRST_FLUSH) li_buf ok).
- 595+ writeback kworker/u9:4 D-state __folio_lock (only hung_task entry ever; folio owner UNPROVEN).
- 763-774 noino-158 release work: whole-AIL min frozen at 0x100000b3f × 8 pushes → designed shutdown.
- 785.056229 P-SHUTDOWN-FENCE ino=23068801 mode=PR comm=bash (TOP of ilock_begin — bash arrived at a
  FRESH xfs_ilock(SHARED) AFTER waking) + 7µs later P71-UNDERFLOW mode=PR state=CACHED dlm_mode=EX.

## Absences that killed each theory (all prints verified live in same boot, none capped out)
- No P1-AGWAIT after 562.271 → NOT in AG on-disk poll.
- No P47-FILEBLOCK / P73-WAITSTALL for the ino → NOT in ilock_begin demote-wait.
- No P34-ACQ-SLOW → never RETURNED from a >1s inode-DLM slow acquire.
- No P70-BP ENTRY for the ino → inode bast_process/self-demote NEVER RAN.
- No P7B-BASTNOTIFY for the ino → no peer BAST on it.
- No P109-EDEADLK prints (gated on instr, but livelock-shutdown print absent too; EDEADLK arm caps
  at 64 laps ≈ ≤60s sleeps → can't fill 222s).
- Inode bast wq = WQ_UNBOUND max_active=32; only ONE noino work in flight → no head-of-line block.
- P12-WORK bail checks saw holders=0 at 60+ samples → bash never held AG-11 after .300.

## GPT-5.6 consult verdict (RULE 5, full dossier)
Leading: log grant-head wait (xlog_grant_head_wait) during defer roll / CIL-iclog wait at commit —
those waiters WAKE PERIODICALLY (push AIL, recheck) so hung_task's no-context-switch detector never
fires — resolves the "not D-state 120s" objection. Also candidate: mxfs msleep-retry loop reachable
from trans commit tail. Folio path ruled unlikely upstream (pagecache work precedes the trans).
The 785 SHARED ilock = open-tail/error-cleanup after shutdown woke it, not the parked section.
Discriminator: bash stack at first AG-AIL stall + log tail/grant heads + i_lock rwsem owner.

## Probe deployed (v0.11.115, srcver CD2AB2017D2E1748A4E514C, prepped 32/caw all 32 nodes)
xfs/xfs_trans_ail.c xfs_ail_push_ag_sync_bounded:
- mxfs_rwsem_owner_peek() (rwsem_spin_on_owner pattern) on the stuck ino's i_lock;
- P67-STALL-OWNER-STACK: throttled (30s) sched_show_task() of the ILOCK owner from inside the AIL
  walk (stall>=4) — THE decisive capture;
- P67-STALL-OWNER line at every stall-abort: item lsn, AIL min, l_tail_lsn, reserve/write grant
  heads, owner comm/pid/state/nvcsw, mxfs_ilk last-locker (wr/rd ret+pid+comm, rd_held, un_ret).

## Repro
tests/repro_32caw_wedge.sh 1 (one ~5min lap per foreground call; chain dlm_scaling→cache_coh→
dir_reuse→fence on 32/caw mpath). Historical hit rate ~1/10 sequences. If dry: add fork-free
python K=32 probe storm concurrently (sess12-B pattern; host load ~30 was live at the 11:11 hit).

## Defect 2 (aged slope) findings so far (code-read, cluster re-prepped so aged artifact gone)
- rerr=-11 DECODED: xfs_iflush_cluster returns -EAGAIN = "nothing dirty to flush" (also
  in_ail-retry arm). P146-RELDUR rerr=-11 on clean inode = benign nothing-to-flush.
- mxfs_inode_cluster_durable loop: per call = maybe log_force(SYNC) + xfs_imap_to_bp (DEVICE READ
  when cluster buf evicted — eviction-ring suspect for aged growth) + every-32nd-lap+lap-0 on-disk
  tenure verify (512B FUA) gated by i_dlm_heldchk_j >100ms (always stale on slow op loop) +
  iflush_cluster. Op-side budget 25×2ms; release-side 1500.
- Aged 4× slope = these per-op reads (sess12 ftrace: ~11 device reads/op). NEXT: find why cluster
  bufs evict per-op on aged (eviction ring? bcache pressure?) and cache/skip the tenure verify.
