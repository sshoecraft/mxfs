---
name: ccloop-c7ee71c6-sess376-closure-hazard-matrix-complete-two-disproofs
description: sess376: #3 Hazards-7 matrix COMPLETE (reuse 3/3 + ABA 2/2 + KILLPUB); 2 defects DISPROVED with code+rig evidence; 3 filed incl. a critical corruption
metadata:
  type: project
tags: [closure-purge, dlm_caw, aba, rule6, fence_during_write, corruption]
---

sess376, builds 0.14.8 sv D15316B499606FC03B8B4C0 then 0.14.9 sv 25057F6813DDAF1ECB477CF, 32/caw.
Board on 0.14.9: 25 PASS / 2 FLAKY(passing) / 0 FAIL / 1 POLICY. Ledger 47 open of 102.

## Two log-reading traps, each of which had cost a session

1. `caw_inject_closure_pause_n` is a SINGLE GLOBAL consumed by whichever caller
   arrives first, and BOTH the publisher purge scan and a blocked waiter's demand
   scrub pass through the same site in caw_closure_strip_one. sess375 read the
   resulting 76s wait as "the demand scrub never fires". It fired at el_ms=1 and
   then slept 75000ms inside the injected pause. New knob
   caw_inject_closure_pause_who (0=any, 1=scan, 2=scrub). Control with who=1:
   P_EX rc=0 elapsed=0 instead of 77s.
   => D-CLOSURE-DEMAND-SCRUB-NOT-FIRING-FOR-BLOCKED-WAITER-375 DISPROVED.

2. "the publisher purges before it publishes" is FALSE. The durable publish is
   mxfs_v5_dlm_recovery_publish_refusal() at xfs/xfs_mxfs_dlm.c:46711; the purge
   scan is :46759; the "terminal outcome PUBLISHED" alert at :46791 is only the
   trailing summary. Un-injected scan wall = 418 ms (P299-CLOSURE-SCAN ENTRY
   14028.136 -> P299-CLOSURE-PURGE 14028.554). Decisive rig proof: a publisher
   destroyed mid-scan never emits that line at all, yet ALL 30 remote survivors
   logged P240-QUAR-IMPORT (~2.1s after their own fence-done).
   => D-CLOSURE-REMOTE-WAITER-NO-REPAIR-BEFORE-PUBLICATION-376 filed and
   DISPROVED in the same session. 8/8 remote probers rc=0 at 62s vs a 120s timeout.

## #3 Hazards-section-7 matrix now COMPLETE

Row 5 (hint->read reuse, A -> tombstone -> B): PASS 3/3, attributed per attempt by
the new P299-HINT-MOVED line naming slot, hint ino and found ino. The aggregate
P299-CLOSURE-SHAPES counters accumulate over a WHOLE 65536-slot scan and name no
slot -- never assert on them alone.
Row 6 (read->CAS window, ABA, A -> tombstone -> A): PASS 2/2 via ABA=1. Same
resource AND same lineage (a same-resource tombstone recycle inherits it via
caw_claim_inherit_epoch) and the CAS still miscompared:
P299-STRIP-CASMISS slot=884 inv=1 retry=0 expect_ino=96469465 expect_gen=2
expect_lineage=0xf5395d36932ba3a6 expect_vfoot=0x1. Retry re-read, bit gone, zero
strips on that slot. Identity semantics: generation is PER-BINDING and restarts at
1 on a fresh claim; a tombstone PRESERVES generation/resource/lineage/ex_grant_epoch.
What actually excludes ABA is that the expected image necessarily carries the
victim footprint and a tombstone requires every holder/waiter/open bit clear first.
Row 7 (publisher death BEFORE publication): new KILLPUB=1 arm, PASS.

## New critical defect found while reproducing a flake

D-FDW-REJOIN-BNOBT-OVERLAPPING-FREE-SHUTDOWN-376. A node just fenced by the
cluster and rejoined hit a free-space double-free in a truncate:
P145-FREE agno=10 bno=9 len=2 while the bnobt already held (10,3) ->
"bno + len > gtbno at line 2490 of xfs/libxfs/xfs_alloc.c" -> xfs_corruption_error
-> "Corruption of in-memory data (0x8) at xfs_defer_finish_noroll" -> P-WITHDRAW,
node never rejoined. Same sequence: fence_during_write FAIL 3/3 including
"fdw node6 own data intact(exp=1 got=0)". Control right after a fresh prep: 3/3
PASS, reconverged in 8s. Trigger NOT identified -- back-to-back fencing is NOT it.
Leading hypothesis (a): D-FOREIGN-SLICE-INTENTS-ABANDONED, an EFI completed twice
(peer replay + rejoined node). Instrument EFI provenance before patching.

## Harness/rig facts worth not re-learning

- prep_cluster DOES mkfs -f (tests/setup/prep_fs.sh:79) and clears dmesg on every
  node: harvest a node's evidence BEFORE re-prepping, it is gone afterwards.
- Restart EVERY destroyed VM before prep, or the marker records an ssh error
  string as the srcversion and every later run errors out.
- Backticks inside the double-quoted remote heredoc in the closure tests are
  command substitution on the LOCAL shell; a prose comment with `moved` ran `moved`.
- The reuse test must HOLD the re-bound resource live across the publisher's wake;
  a single read binds and releases in milliseconds, and a tombstoned slot
  short-circuits strip_one at the magic check (vanished) before the resource
  comparison that scores moved.
- run.sh wait_converged now records RECONV_TRAJ / RECONV_LAST / RECONV_WALL and
  writes trajectory+dissent into criteria.json: an unattributable reconvergence
  flake became "traj flat at 31/32, dissent=[test6=nores]" on first repeat.
