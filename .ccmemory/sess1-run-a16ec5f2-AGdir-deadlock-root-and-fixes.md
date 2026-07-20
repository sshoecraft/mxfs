---
name: sess1-run-a16ec5f2-AGdir-deadlock-root-and-fixes
description: sess1(run a16ec5f2): 4/tcp=6/6 w/ FACE-2 reload retry. 8/tcp root reframed: 61s AG-EX starvation (P36 type=3) while holding dir-131 EX → -110 → dirty…
metadata:
  type: project
---

# sess1 (ccloop run a16ec5f2) — 8/tcp dir_reuse: AG↔dir stall root-cause chain

## Criteria: 1/2/4/8 node tcp dlm test 100%. Marker NOT written.

## Builds this session
- `C10470A6` = sess7(run6614) baseline F5A90E91 + **FACE-2 fix**: bounded imap_to_bp retry (10×3ms on -EIO/-EFSCORRUPTED) in DLM inode reload (xfs_mxfs_dlm.c ~11816). **4/tcp drc_reliability = 6/6 PASS** (was 2/3). KEEP.
- `4EB7B98B` (v0.5.8) = + AG-trylock for single-AG allocs: new `args->mxfs_ag_trylock` in xfs_alloc_arg; prepare_ag uses mxfs_ag_dlm_trylock when set; set/cleared around exact_bno+near_bno in xfs_bmap_btalloc_at_eof + filestreams near_bno. start_ag 2-pass semantics preserved (blocking backstop). ialloc/ialloc_btree/refcount_btree callers untouched.
- `890B1C41` = + attribution instr (all behavior-neutral): P36-RETRY now logs ag=%u comm=%s; P67-AG-BAST-STALL ungated (was mxfs_idbg); P1-AGWAIT (waiter-side, nb-probe→log+dump_stack first 5/boot, then blocking as before) in __mxfs_ag_dlm_lock; P1-AGCONFLICT (master-side, both local+remote compat checks) names GRANTED holder blocking an AG request.

## 8/tcp dir_reuse ROOT (2 instrumented runs, both FAIL 0/8)
**Shape (both runs identical):** one node wins dir-131 EX, its create (dd) then blocks in a FRESH blocking AG-EX acquire (P36-RETRY ino=0 type=3, run1 ag=? pre-instr, run2 ag=0) for exactly 1s+60×1.024s=61s → rc=-110 → `dir_create_child err=-110` → dirty xfs_trans_cancel → **"Corruption of in-memory data" SHUTDOWN** → all peers' readdir=0/800. Dir-131 grant log (master P-DGEX) freezes for exactly that window; peers' dir-EX waits also -110 (their creates fail; some also P-CR3-CANCEL). run1: test8 shutdown; run2: test7 shutdown t=292.
**Where the waiter blocks (run1, pre-fix):** growth/data alloc under held dir-EX. exact_bno/near_bno had alloc_flags=0 → blocking mxfs_ag_dlm_lock on ONE target AG (xfs_alloc.c prepare_ag). Fixed in 4EB7B98B — but run2 STILL stalls (comm=dd ag=0, and comm=rm ag=4 on test1): remaining blocking paths = start_ag/iterate_ags SECOND pass (all-trylock-fail) and __xfs_free_extent (rm side, unfixable-by-skip: free must target its AG).
**REFUTED: holder-side drain wedge.** P67-AG-BAST-STALL fired **0×** cluster-wide in run2 → the AG0 holder's bast drain never even stalled. So the holder is NOT pinned-buffer-wedged. Leading H2: **AG-grant starvation** — __mxfs_ag_dlm_lock fast paths (holders++/cached-reclaim, xfs_mxfs_dlm.c ~18957/18967/19068/19076) do NOT check pag_dlm_bast_pending; a hot AG's affine node re-acquires continuously and the BAST work never gets a holders==0 window (P15-REL-ABORT is the inode-level analog). AG0 is hottest: shared dir ino=131 lives there.
**Also:** `DLM inode lock failed ino=128/131 mode=5 rc=-35` (-EDEADLK, upgrade-conflict denials) on all nodes, 60-85 P36/node — mass dir contention churn but the DGEX handoff chain works (0.3s/owner cycle) EXCEPT during the AG-stall freeze.
**agcount=50** (not 4!) on the 50G LUN. 8 nodes → affinity AGs 0-7 distinct. Steady state: every AG ends up cached-held by SOMEBODY (grants held until BAST) → trylock sweeps fail broadly → blocking second pass carries real load.
**TCP NOQUEUE (mxfs_v5_dlm_ag_lock_nb) IS a real ~ms trylock** (master round-trip; denies w/ MXFS_ERR_DEADLOCK→-EAGAIN). NOT a stub.

## Evidence tooling
- drc harness reports STALE faces: dmesg persists across module reloads; drc_reliability's faces-grep tails whole dmesg. Always cut at last 'Ending clean mount' line. Cross-node clock sync via realns= fields (per-node offset = realns/1e9 − dmesg_ts).
- Dumps: scratchpad run1_8n/, run2_8n/ (test1-8.dmesg per run).
- imap_to_bp failed storms AFTER a shutdown are post-shutdown artifacts (every read EIOs) — not FACE-2.

## NEXT (in flight at background task b1cyalsjm: drc 8 1 on 890B1C41)
1. Read P1-AGWAIT stack (names the exact blocking call path: iterate_ags 2nd pass vs __xfs_free_extent vs other) + P1-AGCONFLICT holder= (names AG0 holder node id + hstate).
2. If H2 (starvation): fix = bast_pending-aware defer in the AG fast-path acquire (mirror inode-side defer_for_waiter sess50) OR bounded-hold/forced-yield for AG grants (MHT-style batch like dirs). NOT trylock-skip of drains (sess7 constraint), NOT unbounded blocking.
3. rm/free side (__xfs_free_extent) needs its own answer if it still stalls (free can't move AGs; candidate: sess58-style pre-acquire of dir-extent AGs before dir-EX, or deferred/retryable free).
4. Node-id→hostname map needed (P-DGEX owner ids like 474873771=test8, 1360329194=test1(run1); confirm per run — ids change per boot? They looked stable per node across run1).
5. After 8/tcp: re-verify 1/2/4 no-regress (4/tcp drc ≥6, plus FULL ./run.sh suites), FACE-1 P132 leak watch (never fired yet this run), then full-suite × all N → marker.

## Constraints carried
- Do NOT trylock-skip drain_evict/consumer_refresh (regresses 4-node 0/4, sess7).
- instr=1 hides races (100x slow) — keep default modargs for repro.
- RULE 0 budgets: drc 4-node ~4min/run, 8-node ~9min/run incl reset.
