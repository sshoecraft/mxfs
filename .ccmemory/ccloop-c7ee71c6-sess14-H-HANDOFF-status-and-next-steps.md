---
name: ccloop-c7ee71c6-sess14-H-HANDOFF-status-and-next-steps
description: sess14 HANDOFF: v0.11.131 state, what is fixed vs still open (cc still fails ~1/3 post-P174), exact next steps + GPT-designed protocol for the remain…
metadata:
  type: project
tags: [handoff, sess14, open, d3, next-steps, gpt-protocol]
---

# sess14-H: HANDOFF — status at v0.11.131 (srcver 7B1BE81C057A1A7B59609E5)

## Criteria answer: NO — not production ready. Do not write the YES marker.

## Fixed this session (with evidence)
- **D1 fence-wedge/spurious-shutdown — ROOT PROVEN + FIXED** (.119, sess14-A):
  cancel_work_sync in the AG pre-CAW/yield drain waited on a work stalled behind the
  caller's own ILOCK. Stack-captured 2×. Non-blocking cancel_work + P67-NOWAIT-SKIP.
  ~20 chain laps since with zero wedges/NO_TERMINAL_RECORD; guard fires constantly (417+).
- **D3 acquire-side root — FIXED, PARTIAL** (.131, sess14-G): cached-EX fast path RMW'd a
  fork never rebuilt across peer modifications (dgen>lgen) and its authorized release drain
  published it. P174-STALEGEN-ADOPT fires ~110×/run; cc went from failing 4-of-6 runs to
  passing 4-of-5. **RESIDUAL: 1 of 3 post-fix cc runs still lost 4 files (8 checks) —
  right after a FRESH prep, so the residual is not aged-state dependent.** OPEN.
- D3 companion fixes, all live and firing: dead-incarnation write-poison (P146D/P32D, .120
  hardened .123), dir-epoch flush fence (P32E, .121), NL-logged dir slot publish guard with
  the RELFLUSH-token predicate (P56-NL-LOGGED-DIR-SKIP, .124/.129).
- D5 partial: instant bail when the reload's caller holds the read lock itself
  (P173-RELOAD-SELFREAD) + spin cap 1000→64 (param reload_wtrylock_spin) + ratelimited the
  BAIL print (was 100k lines/lap ≈ 350 CPU-seconds/lap cluster-wide of pure waste).
- D2: runtime lever mxfs.dirop_sync_barrier (default 1) + the A/B proof that the barrier is
  BOTH the 7.6× slope AND load-bearing (off ⇒ dlm_scaling nodes complete 0 ops).

## Still OPEN (priority order for session 15)
1. **D3 residual** — cc still loses ~4 files occasionally. NEXT STEP: run
   `tests/d3_dirring.sh 1` (auto-harvests all 32 dmesg + P172 rings on failure) or run cc
   and harvest immediately on FAIL — do NOT re-run cc before harvesting, the criteria row
   is overwritten by the next run (lost one failure's detail that way this session).
   Then merge the P56-DIRWRITE ledger (fields now include relflush/dgen/lgen/comm) —
   the analyzer idiom is in sess14-F/G. Expect either (a) another acquire path that skips
   the adopt (slow-path reload guards: P-RELOAD-IDENTICAL, keep-stale, P34J bails), or
   (b) the block-format (non-shortform) dir equivalent — P174 only covers SHORTFORM forks
   on the cached-EX fast path.
2. **GPT's protocol (sess14-D + this session's second consult) is the end-state**, and both
   consults converged on it. Implement in this order:
   a. Strict land-before-release: the release drain must not report success while a
      publication obligation remains (its "nothing dirty/EAGAIN" path currently can).
      Track pending vs durable image seq per inode; a drain that cannot land must fail the
      handoff (fence/withdraw), never release silently.
   b. Acquire-side: no tenure may mutate a dir whose fork is not proven current
      (loaded_epoch == authoritative grant epoch). P174 is the narrow version of this.
   c. Then the write-side guards become pure assertions.
   NEVER union whole shortform images (trades lost-adds for resurrected-removes).
3. **D2** — implement deadline visibility-tickets (sess14-D): ~2ms coalesce, 5ms
   backpressure, expedite on BAST, pin EX until the ticket lands, drop the per-op FUA
   readback. Should re-green drc rounds_done>=8 (chronically 6-7/8 at 102-118s).
4. **D6** — bnobt lost-update withdrawal (sess14-E), evidence in
   tests/logs/bnobt_20260726_1827_test10/. Suspect fenced-peer slice replay vs live AG.
5. **D4** — sf_verify NULL panic: guard holds (zero occurrences in ~20 laps), root breach
   unlocated; P171-SFNULL trap armed. Restore panic capture (netconsole → clyde).

## Harness/infra notes learned this session
- run.sh's pre-assert fails on many nodes right after a FAILING dir_reuse_coherency (its
  teardown leaves mounts down) — harness ordering artifact, not an mxfs defect; re-prep.
- The aggregate `measured` field can read failed=0 on a REAL multi-node loss (it is
  rank1-derived) — always check `.reason` for per-node check names. d3_dirring.sh now does.
- tests/d3_ring_analyze.py merges the P172 rings; tests/d3_dirring.sh runs the recipe and
  captures automatically.
