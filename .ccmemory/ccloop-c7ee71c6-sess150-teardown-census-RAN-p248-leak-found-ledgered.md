---
name: ccloop-c7ee71c6-sess150-teardown-census-RAN-p248-leak-found-ledgered
description: sess150: teardown census RAN on 0.11.453 — lifecycle PASSED on 32/32 (clean departures, probes silent) EXCEPT new defect D-RELEASEALL-LREQ-RETIRE-MIS…
metadata:
  type: project
tags: [mxfs, sess150, teardown, lreq, P248, release_all, defect-ledger, gpt-ruling]
---

# sess150 — teardown verification executed; one new defect found, ledgered, fix designed + consulted

## What ran (the sess149 plan, completed through the consult)

1. Baseline census: all 32 on srcversion F20024E38213A9E64DB6718 (=0.11.453), mounted, 0 teardown-probe hits.
2. `./run.sh 32 caw prep_cluster` — 58s (budget 300s). First-ever execution of the landed
   lifecycle stop() (sess131-135 work) on the deployed build, on all 32 nodes.
3. Post-census verdict: **lifecycle teardown PASSED fleet-wide** — every node logged
   `disklock: released heartbeat slot N (clean teardown)` (= depart_clean true); zero
   P253/P255/P258/P259/P260/P261/P262; zero P257 in the final window (test19's p257=1 is
   HISTORICAL, uptime 64352 ≈ prior teardown, and was the designed owed=1 path).
   P109 cas_rc=-11 lines are BENIGN (attempt-0 CAS contention; P109 prints only retry==0's rc;
   the 20-retry loop converged or P257/P259 would have fired).
   P-GOODBYE-SENT absence is CORRECT under CAW: ctx->dlm/ctx->peer are created only in the
   MXFS_V5_TRANSPORT_TCP branch (v5_mount.c:3341); the heartbeat-slot release IS the CAW
   clean-departure publication.

## The new defect (ledgered: D-RELEASEALL-LREQ-RETIRE-MISSING, major)

P248-LREQ-LEAK entries=6 guard=0 defer=0 owed=0 exhaust=0 nomem=0 on ALL 32 nodes.
Exact 1:1: P109-CLR-RELEASE-ALL lines in each node's final DLM-shutdown window == 6 == leaked
entries, 32/32. Root (code-confirmed): `caw_release_all_body` (dlm_caw.c:9693; per-slot loop
~9789-9905) does untrack_held on confirmed CAS clear but NEVER `lreq_release_all` — the retire
the single-resource unlock path performs at ~8407. Entries with live tenure survive to
`mxfs_dlm_caw_destroy` (~12250) which frees+reports them. Consequence: P248 fires on EVERY
clean teardown → the teardown-integrity signal for lreq_gc's UAF-protective refusals is dead.

## GPT consult (RULE 5, done this session) — binding design points for the fix

- **Sample pub_seq0 ONCE per resource identity when it first enters the release, BEFORE its
  first CAS. Do NOT re-sample per retry** (re-sampling moves the release boundary forward and
  can eat a publication landing between a CAS failure and the next sample).
- **On resource-identity churn across retries (memcmp differs — lreq_find at 1802 uses memcmp,
  so memcmp IS the canonical compare): DECLINE the blanket retire entirely** (fail-closed; the
  entry survives to the P248 destroy report, which the new dump will name). A→B→A needs history
  to handle correctly; declining is the approved conservative shape.
- pub_seq==0 as no-entry anchor is SAFE: the only bump is dlm_caw.c:4614 (`e->pub_seq++`),
  so a published entry always reads >=1; retiring against anchor 0 can only no-op an idle entry.
- Peek and compare are in the same serialization domain (both under ctx->lreq_lock). Keep
  untrack_held-then-retire order (tenure keeps the entry non-GC-eligible in the interval).
- Do NOT retire the not-cleared-but-owed case (obligation must keep the entry for collector/verdict).
- Change B (stuck-notify wiring): SHUTDOWN_META_IO_ERROR (not CORRUPT_INCORE). Work item
  embedded in per-mount; teardown order = v5 destroy FIRST (stop() joins the owed worker — the
  only emitter; caw_owed_fail_notify at 4710 re-reads fn under lreq_lock but invokes outside it,
  so the join is the synchronization) THEN cancel_work_sync THEN free; mirror on mount-failure
  unwind; cancel-not-drain is fine if logged. Registration site: where XFS registers other v5
  notifies in xfs_mxfs_dlm.c. A+B in one build OK (disjoint verification signals).

## Implementation state (task #1 in_progress, nothing edited yet)

- Helper `lreq_pub_seq_peek(ctx,res)` → place after lreq_release_all (~4975, before 9693).
- Edit 1: per-slot loop — declare pub_seq0/seq_sampled/seq_churned/seq_res; sample after
  `res = cur_slot->resource; res_known = true;` (first identity only; churn → seq_churned);
  after loop: `if (cleared && res_known && !seq_churned) lreq_release_all(ctx,&res,pub_seq0);`
- Edit 2: P248 identity dump in destroy loop (~12274): before mxfs_pal_free(e), first 8 entries,
  print type/id/tenure[]/pub_seq/attempts/writers/pin/clr_active/owed_pend/busy/oq_queued.
  UNRESOLVED: MXFS_LOCK_MODE_COUNT value/location (referenced dlm_shared.h:40; find the enum);
  dlm_caw.c has ZERO scnprintf/snprintf uses — check compat/ for what string formatting is
  available in the dual-build (or print tenure as fixed fields).
- Then: rev VERSION patch (0.11.454), build, deploy fleet, `./run.sh 32 caw prep_cluster`,
  census P248==0 fleet-wide + all other teardown probes still silent.

## Also this session

- Ledger: added the new entry (69 total) AND refreshed D-FOREIGN-REPLAY-UNGATED-IMAGES's stale
  `next` (was sess98-era; now points at: stuck-notify wiring, begin_release dead hook vs sess104
  ruling, lifecycle re-consult + sess96 producer-half redesign as the remaining core).
- Tasks: #1 P248 fix (in_progress), #2 stuck-notify wiring, #3 lifecycle re-consult + deploy +
  full board, #4 compile-memories (COMPACTION DUE, 189 unfolded — still not done, backlog grows).
- Cluster left mounted+converged 32/caw on 0.11.453 (prep marker current).
