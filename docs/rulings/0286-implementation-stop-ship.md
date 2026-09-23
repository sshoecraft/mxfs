<!-- sess418 RULE-5 review of the 0.29.0 D-0286 session-poison landing: STOP-SHIP — 9 closure conditions (linearization, RX TOCTOU, remaster reconstructio… -->
# sess418 GPT review (gpt-5.6-sol) of the 0.29.0 D-0286 landing — STOP-SHIP

## What was landed (0.29.0, sess418) before the review
- pal.h: mxfs_atomic32_cmpxchg / xchg (kernel + userspace).
- v5 ctx: depart_state {ACTIVE, CLEAN_LEAVE, POISONED} + withdraw_done.
- mxfs_v5_dlm_poison(ctx, why): non-sleeping; xchg->POISONED, withdrawn=true; called SYNCHRONOUSLY from the
  XFS hook mxfs_dlm_shutdown_withdraw (xfs_do_force_shutdown) before schedule_work.
- teardown: cmpxchg ACTIVE->CLEAN_LEAVE right after depart_clean is computed (P-DEPART-POISON-WINS on failure).
- NODE_LEAVE RX: ignore goodbye from dead / recovery-pending sender (P-GOODBYE-DEAD-IGNORED).
- v5_tcp_declare_dead: fence + note_dead, then if victim owns a HB slot -> NO purge/unregister/refresh
  (P-TCPDEATH-DEFERRED); recovery completion purges.
- KEY CODE FACT: on TCP mxfs_dlm_release_all frees only the LOCAL table — sends nothing; the goodbye is the
  only wire-visible teardown release.

## Ruling: STOP-SHIP, 9 closure conditions
1. Clean-leave/poison need a REAL serialized linearization: the CAS alone lets poison land after the CAS but
   before/during the goodbye send. Either commit+enqueue goodbye under a lock (poison cancels an uncommitted
   goodbye; a committed one is irrevocable) or PROVE (joins/barriers/asserts) no poison source can execute
   after the commit. Poison must NOT overwrite CLEAN_LEAVE (terminal->terminal is wrong).
2. RX TOCTOU: dead/pending check vs death-thread marking must be serialized under one per-node state
   (LIVE->CLEAN_PURGING vs LIVE->DEAD_PENDING; exactly one wins).
3. Messages must be incarnation-qualified (delayed old NODE_LEAVE vs same node-id new incarnation).
   (Tree fact: sess11 P164 dead-set retires an id forever at the receiver, incl. clean departers — same id can
   never rejoin, which answers this by construction; record the evidence.)
4. Global poison must gate ALL wire-visible relinquishment (a non-wedged inode's RELEASE after poison), race-safe
   vs in-flight ops.
5. TCP death must directly enter the certified disk-recovery machine (durable intent -> fence -> cert -> pending
   -> elect -> replay -> purge), not "bare fence then hope the monitor notices"; slot match must be
   incarnation-qualified, not just find_node_slot>=0.
6. A timeout may NEVER fall back to uncertified purge (retry/re-elect/withdraw/freeze/operator only).
7. withdraw_done is racy (two callers both see false) -> atomic test-and-set; gates should read depart_state
   with proper ordering, not plain bools.
8. MASTER FAILOVER RECONSTRUCTION (independently STOP-SHIP): mastership = hash % active_nodes; when the MASTER
   of R dies, its in-memory table dies with it; after recovery completes and it leaves active_nodes, R remaps
   to C which has NO record of survivor B's grant -> "no record => free" -> conflicting grant. Needs a rebuild
   protocol (survivors report held locks to new masters under a generation-fenced barrier before admission).
   If none exists in the tree it is a separate critical defect and a closure dependency of 0286.
9. Deterministic tests: sender race (5 injection points around CAS/enqueue/send/slot-release), RX race, delayed
   old-incarnation messages, release-after-poison of a second resource, in-flight request teardown, TCP-dead-
   disk-alive matrix, master-loss reconstruction, concurrent shutdown callers, replayer crash matrix.

## Session-side answers already established / to verify
- D (sync poison from shutdown context): correct direction; check mxfs_pal_log cannot sleep; ctx lifetime.
- B: after a bare PREEMPT the victim's HB writes conflict -> HB stops -> stale ACTIVE sector -> ANY survivor's
  monitor rediscovers the obligation (durable by the victim's own sector, sess66 note) — argue this with the
  disklock HB-write-failure code, and keep "purge anyway" out of every timeout.
