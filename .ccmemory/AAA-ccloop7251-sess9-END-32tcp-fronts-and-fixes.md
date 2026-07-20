---
name: AAA-ccloop7251-sess9-END-32tcp-fronts-and-fixes
description: sess9 end-state: tcp 1-16 GREEN; 32/tcp 18/19 (drc pace front open: 300ms round-open handoffs on TCP). 0.11.35=30FA152F. 3 kernel fixes + methodology…
metadata:
  type: project
tags: [ccloop-72513a13, sess9, tcp, drc, handoff]
---

# sess9 handoff — where everything stands (build 0.11.35 = 30FA152F1C51A1AEC9F915F on 32/tcp rig)

## Matrix: tcp 1=29/29 2/4/8/16=20/20; 32/tcp = 18/19 green on-record (0.11.33-era rung) with drc@32 THE open front. cawd+caw complete (older builds). cawp untouched.

## KERNEL FIXES LANDED THIS SESSION (all in 0.11.35):
1. **P152 trans-drain punt (0.11.32/33)**: mxfs_trans_drain_inode_unlocks self-deadlock
   (rename final-commit holds ILOCKs at trans_free by modern-XFS design; deferred
   bast_process's AIL drain needs those ILOCKs — P113 22k-iter wedge, live test8
   dossier tests/logs/tcp16_dlmscaling_wedge_20260719/). Punt to i_dlm_bast_dwork
   when ILOCK owner==current, restoring CACHED+bast_pending under i_dlm_lock first.
   CONFIRMED WORKING: qsrc=16 P70-BP entries on test17 processing cleanly.
2. **demwait_redrive inline release (0.11.33)**: igrab-refusal on FREEING inode left
   dead-DEMOTING unclearable while the WAITER was the eviction itself (test4 29-min
   3s-cycle P-DEMWAIT-REDRIVE/P134 ping-pong at 32/tcp drc). On igrab fail run
   mxfs_dlm_bast_process(ip) INLINE (frame pins struct; no ILOCK held; xfs_mxfs_dlm.c
   ~22253).
3. **TCP epoch-consume adopt (0.11.35)**: dropped the transport_caw qualifier at
   xfs_mxfs_dlm.c ~17172 (ea_adopt = param || ea_self_clean). RULE-4 basis: 61s drc@32
   repro — test21 ran round 3 on a stale DEAD dir incarnation (readdir 0/128, its 4
   creates orphaned = the 4 missing names cluster-wide; ZERO P63 on victim). Guards
   kept: post_release=1 + clean-self. RESULT: dirent-loss class GONE in subsequent
   runs (readdir 128/128 everywhere); 8/16-node regression check still owed.
4. **Probe-storm caps (0.11.34)**: P82-ADD/P140/P25-INSTR×2/P19(8000→300)/
   P2L-EX-GENMIS(3000→300)/P2L-INACT-LEAK(unlimited→300)/P61(6000→300)/P71(2000→300).
   Basis: 22,822 dmesg lines/145s on test17 during drc@32 rm = printk-serialized DLM
   service blackout — test1 P-LKTIMEOUT-REMOTE ×119 (~130s) against test17 while
   test17 never processed the requests. **P2L-INACT-LEAK fired 2001× = the P2I
   demote+reacquire fix is NOT holding at 32/tcp — REAL AGI-bucket leak regression,
   OPEN FRONT** (comment at xfs_inode.c ~3700 says must-be-zero).

## OPEN FRONT: drc@32/tcp pace (5-6 rounds/110s vs MIN 8; rounds 19-22s vs 12.5 needed)
- RULE-4 SPLIT DONE: round-open transient = THE term. wave1 (64 creates) = 9.95s,
  then sync+wave2 (64 more) = 40ms. 10s/32 hops ≈ 312ms/handoff = inode_mht_ms=300
  window: 32 nodes' FIRST claims on the fresh dir each wait the full 300ms window —
  the sess7 quiet-age gate (grace-slice dwork release at ~40-55ms quiet) is NOT
  engaging on TCP for this shape. held_ms=301/304 confirmed on sampled P70-BP.
- NEXT RULE-4 STEP: on the round-open holder, trace bast_pending arrival time vs
  claim time (P-DIRBAST print exists) — is the TCP BAST delivered promptly when
  waiter #2 queues at the master? Suspects: (a) master defers BAST send on TCP
  (P6-FAIRQ queues silently), (b) mht_defer_bast never armed because bast_pending
  arrives only after window expiry, (c) quiet-gate armed but dwork starved.
- Same term explains the 4-5s create phases at 16/tcp (16×300ms) — fixing it speeds
  the whole ladder's drc. Test-side already optimal (fork-free pattern batches
  perfectly once rotation warms: 64 creates/10ms).
- Diagnostic markers wave1-done/sync1-done/wave2-done are LIVE in the test now.
- ALSO seen once on 0.11.35 run1: round-abort ROUND_FAIL rank=15 readdir=128/128
  lookup_fail>0 = leaf-hash-hole class resurfaced 1× — watch for it in re-runs.

## Test/infra landed: pm wipe (degeneracy), drc fork-free+2-syncs-dropped+wave markers,
## tds N-invariant (1600/T floor 50; 31-44s at 16/32), fio rand 128/N floor 8m
## (FIO_RAND_SIZE), run.sh prep step-1b /src NFS self-heal (was 2 aborted rungs),
## raw_fio_ceiling median-of-3 (.raw_fio_ceiling.tcp.json has all 5 Ns),
## dir_add_visibility diagnostic + scripts/run_adhoc_suite_test.sh.

## 32/tcp CALIBRATE BUDGET DEBTS (recorded PASS, over budget): fio 127/120,
## cc 93/60, pm 34/30 (wipe adds ~4s at 32), fairness 49/30, crash 113-120/90.
## Must close before final enforcing sweep (or budgets are re-argued with user data).

## Sequence to finish: (1) close drc@32 pace via the round-open handoff fix,
## (2) re-record drc cells 2-32 + regression 8/16 on final build, (3) budget-debt
## shaves at 32, (4) cawp ladder (rig.sh cawp 32; 6 rungs), (5) 8/cawd + spot cawd/caw
## regression on the final build (epoch-adopt now unified — low risk, ea_self_clean
## unchanged on CAW), (6) full one-build sweep + criteria marker.
