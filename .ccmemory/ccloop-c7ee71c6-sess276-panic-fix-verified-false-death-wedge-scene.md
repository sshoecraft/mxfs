---
name: ccloop-c7ee71c6-sess276-panic-fix-verified-false-death-wedge-scene
description: sess276: agwait ihold panic FIXED+VERIFIED 0.11.498; dlm_fairness live scene: test5 false-death fenced (D-482), P227 refusal wedges fleet, victim P15…
metadata:
  type: project
---

# sess276 — panic fix verified; live mass-false-death wedge captured

## 1. Agwait ihold/irele panic: FIXED AND VERIFIED (0.11.498 sv 18848B9F349CD23E496A68B)
GPT-approved deletion of ihold/xfs_irele in mxfs_trans_agwait_handoff
(inodes are BORROWED against caller frame; evict is the lifetime in the
inactivation path). Verification: 3× rsync_paired PASS 32/32 (18-20s) +
3× scaling_curve PASS 32/32 (42-48s) + board chunk A through
zero_silent_loss PASS; P271-AGWAIT-SEAM/PREACQ fired dozens of times
fleet-wide incl rsync rename 3-inode handoffs — zero WARN/BUG.

## 2. LIVE incident during dlm_fairness (30s budget timeout → fleet wedge)
Timeline (test5/test7 clocks comparable, both booted ~18:31):
- test5 remounted at prep as node 2162251905 slot 26 (fresh claim, slice
  ADOPTED). Slot 28 node=1459181881 = test5's PREVIOUS incarnation
  (sess275 panic), correctly declared dead later.
- ~1288s test5: P70-BP held_ms=64867 on ino=128 (root dir) + P-PRSWEEP
  released 306 idle PR grants — dir-lock BAST storm from dlm_fairness.
- 1291s test7: P6H-HANDOFF ino=75499837 (contended dir) to_slot=26.
  test5 NEVER saw it: P-ACQ-STUCK polls showed gen=332 hex=2 (slot 1 EX)
  frozen for 120s while platter reached gen=383 hex=4000000 (slot 26 EX,
  test1's view). test5's slot-15378 view stale by 51 generations.
- ~1325-1387: test5 HB stopped landing (31 checks × 2s); ALL peers fence
  slot 26 (prover node 107649458, term=1). NO instrumentation for WHY the
  HB writer stalled — D-482 arm A still unbuilt. Device paths healthy
  post-hoc (inflight 0/0, both mpath legs active ready).
- Post-fence test5: 5842+ SCSI reservation conflicts; CAW unlock CAS fails
  -5 → P274-UNLK-CAS-ERR outcome UNKNOWN; P15-REL-ABORT spin at ~1ms
  cadence on ino=75499837 (orph=1, age 203s+, init_seq=1380, gen frozen
  7517) re-arming BASTs → fleet-wide P-DIRBAST storm.
- test1 (lowest live slot 0) claimed recovery (P236-RECOV-CLAIMED stage=2)
  and REFUSED replay: P227-FR-TORN-UNPUBLISHED slot 26 (1 committed
  untagged image) → slice stays unpublished → P163-RECOVERY-PENDING purge
  deferred forever → fleet writeback frozen (sync wedged in
  wb_wait_for_completion on ~15 nodes), dlm_membership/dlm_scaling BLOCK.

## Defect mapping
- D-482 (mass false death): fresh repro; trigger = 32-node dir-lock
  contention storm (dlm_fairness); arm-A HB-writer watchdog still needed.
- D-FOREIGN-REPLAY-UNGATED-IMAGES (#1): P227 refusal with no token path
  = THE motivating scenario; cluster has no forward path after refusal.
- Fenced-victim noncontainment (NEW face): victim stays mounted, spins
  P15-REL-ABORT at ~1ms, floods fleet with BASTs, never withdraws despite
  persistent reservation conflicts. Ledger it.
- rsync run2 FAIL from sess275 board = the panic (now fixed); dlm_fairness
  FAIL this session = this incident.
