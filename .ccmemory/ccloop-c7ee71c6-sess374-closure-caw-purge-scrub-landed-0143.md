---
name: ccloop-c7ee71c6-sess374-closure-caw-purge-scrub-landed-0143
description: sess374: #3 out-of-closure CAW selective purge + survivor demand scrub LANDED, 2 GPT review rounds folded in, 0.14.3 sv DA8D50EBF86F28CAECF7C54 — not…
metadata:
  type: project
---

# sess374 — D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356 fix landed 0.14.3

sess365-373 all died at startup on a bad model selection (zero assistant
turns each). No work lost; sess364's plan was still current.

## Build
VERSION 0.14.3, `make clean && make modules` + `make tools`,
mxfs.ko srcversion **DA8D50EBF86F28CAECF7C54**. NOT deployed.
Rig still on 0.14.1 sv BDEB75D40B5BE7C21C82EF6.

## What landed (sess364 plan + 2 RULE-5 review rounds)
- dlm_caw.c: `caw_strip_node_state()` (the shared strip discipline; the full
  purge body now calls it) + `caw_victim_state_mask()` (the 9-bitmap union;
  `caw_purge_candidate` is narrower and must NOT be reused — it predates
  waiters_ex/yield_to).
- dlm_caw.c: `caw_closure_strip_one()` = reread -> reclassify -> regate ->
  CAS -> tombstone -> grant mcast wake. `mxfs_dlm_caw_purge_victim_selective()`
  (batch find, one victim, phase-0 gate, partial never = success).
- dlm_caw.c/.h: scrub oracle `closure_scrub_fn` + skip-only hint
  `closure_cand_mask` (volatile u64) + `noq_scrub_busy` atomic32 try-lock.
  `caw_closure_scrub_slot()` allocates its OWN scratch.
  Hook A = caw_wait_for_grant after the magic check (first try immediate,
  2s re-arm, `continue` on strip). Hook B = NOQUEUE conflict exit
  (atomic winner election, still returns -EAGAIN).
- disklock.c/.h: sess361 record-table purge DELETED (wrong table, sess362).
  `closure_gate_predicate` + `mxfs_disklock_closure_gate_snapshot` /
  `_gate_revalidate` / `mxfs_disklock_terminal_gate_check` (LEASELESS).
  Every gate = its own fresh 512B read; an unreadable gate is now a REFUSAL.
- v5_mount.c/.h: purge fn takes expect_victim+expect_ag_mask (-ESTALE on
  drift); `v5_closure_scrub` oracle; `closure_lock` mutex serializes the
  3 cand-mask producers; both CAW oracles unregistered after an explicit
  `mxfs_dlm_caw_stop()` and `ctx->dlm_caw = NULL` after destroy.
- xfs_mxfs_dlm.c: call site passes ocanon.victim_node/ag_mask, logs
  complete/INCOMPLETE; `mxfs_dlm_closure_classify_cb` registered next to
  set_quarantine_cb.

## GPT review round 2 — dispositions
FIXED: atomic cand-mask update (mutex; PAL has no atomic64), atomic NOQUEUE
throttle (inc-returns-new try-lock), private scrub buffers, open_holders via
the shared helper, error propagation + P299-SCRUB-ABORT, immediate first
attempt, stop-then-unregister-then-destroy.

REFUTED WITH EVIDENCE (do not re-open without new facts):
- "missed wakeup: cand bit lands while waiter sleeps" — the CAW wait loop is
  a POLLING loop. dlm_caw.h:58 POLL_MAX_MS=25, dlm_caw.h:71 DEFER_POLL_MS=250
  (the hopeless-defer path). Worst case the hook re-evaluates 250ms later.
- "hold the publisher lease on partial purge" — sess363 ruling item C says
  verbatim "no retry loop, release lease regardless"; the retry protocol IS
  the leaseless survivor scrub.
- "fencing may not be storage-level" — certificate evaluator disklock.c
  ~4925-4967 requires stage>=FENCED, refuses QUARANTINED, requires
  fence_kind proving exclusion, and for PREEMPT_ABORT_DONE requires
  WR_EX_RO at the verify. Plus the victim SELF-FENCES: hb_own_record /
  hb_cas_own_slot (disklock.c 806-853) return -EPERM once its own sector
  holds a RECOVERY_GUARD.
- "slot reuse orphans the old CAW bits" — the full purge's HB-zeroing gate
  refuses QUARANTINED (P234-PURGE-FROZEN, disklock.c ~2780-2820), so a
  quarantined slot is never retired or re-taken while the verdict stands.

## Next
Deploy 32/caw + sess360 dirty-kill repro. PASS = P299-CLOSURE-PURGE
purged>0, survivor root touch OK, quarantined-AG ops EIO, HB sector never
zeroed, P299-SCRUB-STRIP on a blocked survivor. Then the ruling's fault
tests (sess363 memory, "Hazards" §7).
