---
name: ccloop-c7ee71c6-sess270-488-fifth-face-own-bit-orphan-test28-specimen
description: sess270: -488 5th face = ORIGINAL own-bit orphan, live specimen: test28 demote-churn ag=3 → tenure lost, bit28 EX stays, local ag=3 BASTs go silent
metadata:
  type: project
---

# sess270 — fifth face root-narrowed: own-bit orphan on test28

## Chain (all evidence cited, no guesses)
1. run2 (rsync_paired on 0.11.495) wedged BEFORE any death: fleet-wide
   P5N-AG-ORPHAN-NAK ag=2+ag=3 from 17:15:44Z (test1 dmesg 16016-16024).
2. Orphan origin — test28 (hb slot 28, node 26283259), journalctl -b -1:
   - 17:15:52-53: 8× rapid cycles of acquire (P150 tenure 7→9) →
     P12-WORK ag=3 "COMMIT demoting" (BAST ping-pong under contention).
   - 17:15:54 onward: its OWN rsync 5582 + kworker u11:3 block
     "P1-AGWAIT ag=3 peer-held" forever; ZERO further ag=3 events on
     test28 (no P12-AGBAST-RX ag=3, no P12-WORK ag=3, no P5N ag=3) for
     its final ~50s, while it processes/NAKs ag=0/1/2/4/5 BASTs fine.
   - Last AGBAST-RX ag=3 (17:15:44): sched=1 readopt=356..452 page_ms~5000.
   - Platter (caw_slotdump on test1 /dev/sdb): ag=3 slot=50128 gen=128
     ex=0x10000000[28] wait=0x8[3] ex_epoch=41 — test28's own bit EX,
     test2 waiting. Own bit + no in-core tenure + local BAST silence.
3. run3's prep power-cycled the 7 wedged nodes ~17:16:42 (test21/test28
   -b -1 end mid-normal-traffic, no panic). Peers detected HB expiry
   17:17:50 (fleet t=16142-16145): slots 2,6,27,28,29,30,31.
4. Foreign replay of ALL victims refused TORN -117: ATOMIC-SKIP on
   transactions with TOKENSUM classless=1 (untagged images — defect #1
   D-FOREIGN-REPLAY-UNGATED-IMAGES territory) → "grants stay frozen"
   (fail-closed, by design) → ag=3 strand became PERMANENT.
5. Fleet after: test6,8,18,20,21,28,32 up-unmounted; test2 rsync 13975
   blocks rc=-110/120s in xfs_dialloc; runs impossible until re-prep.

## RULE 4 state: hypotheses OPEN (code not yet read)
- H1: demote path's on-disk release CAS miscompares (waiter rewrites,
  slot gen=128) and the failure is swallowed while in-core tenure is
  dropped → own-bit orphan. Audit mxfs_v5_dlm_ag_unlock / dlm_caw CAS.
- H2: bast_scheduled latch stuck true after final COMMIT demoting →
  later ag=3 BASTs merged away AND P5N/strand-repair path never runs
  (it's presumably gated on scheduling the work) → total local silence.
  sess241 suspect list said exactly this ("bast_scheduled stuck true").
- H1+H2 can both hold: H1 strands, H2 blocks self-repair.
- NOTE: P12-AGBAST-RX prints sched=1 even in healthy flow; silence, not
  sched value, is the anomaly.

## Notable secondary facts
- ag=6 platter slot: gmode=NL with wait_ex=bit31 (dead slot 31) — a dead
  waiter bit persists; check whether a stale wait bit blocks grants.
- hb flags=3 (vs healthy 1) marks the latched-TORN/frozen dead slots
  (2, 28, 31 at dump time).
- P-H22-PURGE-MASK purged INODE slots for dead bits 29/30, but AG slots
  of TORN victims stay frozen (P163-RECOVERY-PENDING → refusal path).
- Board's rsync_paired FAIL hostload=13.58 — clyde load high during
  run2; may have widened the contention storm but wedge is FS-side
  (strand persists on idle fleet).

## Next
Read bast_work_fn/demote/sched-latch + CAW unlock CAS error handling,
RULE 5 consult, fix shape: (a) never drop tenure on failed release CAS,
(b) orphan self-repair must run despite sched latch, then full re-prep +
3× rsync_paired + 3× scaling_curve + board.
