---
name: sess16run-P106-overlap-INCONCLUSIVE-instr-incomplete
description: sess16(ccloop) CORRECTION to the P106-overlap lead: it is INCONCLUSIVE. P106-EXGRANT fires ONLY on the slow-path fresh acquire (xfs_mxfs_dlm.c:11765)…
metadata:
  type: project
---

## sess16 (ccloop) — P106 overlap is INCONCLUSIVE (instrumentation incomplete)

Correction to [[sess16run-PIVOTAL-P106-overlapping-EX-grants-and-timing-race]]: the "pervasive overlapping EX" cannot be trusted.

### Why
Per-node P106 counts on the run: test1 grants=25 rels=88, test2 16/50, test3 25/91, test4 28/93. EXREL fires ~3-4× more than EXGRANT. P106-EXGRANT is emitted ONLY on the slow-path fresh-acquire branch (xfs_mxfs_dlm.c:11774, right after the "ACQ-FRESH" set at 11765). The FAST-PATH cached-EX serve and the PR→EX UPGRADE grant the lock WITHOUT hitting that site → those grants are unlogged. So a node shows sequences like [REL REL REL GRANT REL REL REL GRANT] — releasing EX repeatedly with no logged intervening grant. A single-holder pairing over only the logged grants is therefore meaningless → the dozens of "X grants while Y holds" lines are tracking artifacts, NOT proven double-grants.

### What's still TRUE and useful
1. The dir_reuse mht=50 loss is a TIMING RACE (a dirwr=2 run PASSED 8/8; tracing masks it). Validate fixes ONLY at dirwr=0/instr=0.
2. 5 buffer-coherency levers REFUTED at mht=50/dirwr=0: force_coherent, dir_postread_reread, b_mxfs_dir_epoch trigger, dir_release_fua_write, dir_release_invalidate. The clobber is not fixed by any read-side re-read or release-side invalidate.
3. The PROVEN mechanism remains the P-DIRWR count regression (peer writes daddr=120 count=126, another node writes count=77) [[sess16run-BREAKTHROUGH-dir-EX-handoff-midtransaction-lostupdate]].

### NEXT SESSION — to settle double-grant vs cross-tenure-stale-base (the two surviving hypotheses)
Add COMPLETE EX grant/release instrumentation FIRST: emit an always-on (lightweight, not dirwr-gated so it doesn't mask) "EX-HOLD-BEGIN ino realns node" at EVERY path that makes ip->i_dlm_mode==EX usable (slow-path acquire AT 11756, fast-path cached serve, PR→EX upgrade AT the mode>cur set, EDEADLK-recovery regrant) and "EX-HOLD-END" at every transition out of EX (unlock, demote, bast NL). Verify cross-node clock sync (chrony offset) before comparing realns. Then reproduce at dirwr=0 (use this lightweight probe, NOT dirwr=2 which masks) and check: at a daddr=120 count-regression clobber, do two nodes' EX-HOLD intervals truly overlap?
- Overlap → DLM mutual-exclusion bug; fix in dlm/ grant path (suspect the direct PR→EX upgrade / REAFFIRM at dlm.c:512-527 issuing EX without serializing vs the prior holder's outstanding release/drain).
- No overlap → cross-tenure stale-base buffer kept by the anti-resurrection guard; implement GPT design parts 1+2 with the REVOKING fence [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]].

### Build 42178C17 (new logic gated off at default; mht=300 dir_reuse PASS unregressed). Criterion NOT met.</body>
