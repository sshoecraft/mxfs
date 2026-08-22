---
name: ccloop-c7ee71c6-sess189-GPT-ruling-mount-admission-barrier
description: sess189 RULE-5 ruling: mount barrier = ADMISSION barrier. Shape A (top-of-round mphase drain) + B (pending-descriptor fold) + gate-until-complete; pe…
metadata:
  type: project
---

# sess189 GPT ruling — mount recovery barrier is an ADMISSION barrier

Defect: D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE remount arm.

## Measured root (sess189, from sess188 run log)
- Remount: P274 skip keeps WITHDRAWN slot 0; monitor consumes it during DLM
  init (WITHDRAW-SEEN 1102.427 → fence cert overwrites the hb sector →
  P233-MPHASE-DEATH 1102.499 records mphase_dead_mask=0x1).
- Step-6.5 withdrawn scan (~1102.50) finds nothing — sector no longer WITHDRAWN.
- Barrier loop is `for (round=0; todo && round<4)` with todo=cohort=0 →
  loop never runs → take_late_deaths NEVER CALLED despite the record being
  34ms old. Replay went async (settle dispatch) after mount live → stale
  in-core root hides replayed marker.

## Ruling (gpt-5.6-sol)
Shape A alone insufficient. Required:
1. **A**: drain mphase_dead_mask at TOP of round 0 and every round; zero
   cohort must not bypass the drain. (sess62 6B already implies this.)
2. **B**: sweep durable recovery-pending descriptors, fold unowned pending
   slices into the barrier rounds (recovery_acquire + inline replay).
   -EBUSY (owned elsewhere) is EXPECTED, not alert-worthy.
3. **Admission gate**: ownership/progress != completion. If ANY applicable
   pending descriptor remains (any pending slice whose journal could touch
   shared metadata = all of them, incl. root inode), the mount must stay
   admission-blocked: wait/poll bounded for the owner to complete (then
   invalidate cached views again before opening), else FAIL the mount.
   The 4-round cap bounds inline replay discovery, NOT permission to go
   live with leftovers.
4. **T1-T2 protocol fix**: fence pipeline must durably publish
   recovery-pending BEFORE replacing the WITHDRAWN stamp (or make the cert
   discoverable as requiring-recovery); final admission check must be a
   stable cut serialized with pending producers.
5. Accounting: take() = atomic transfer (settle must not double-dispatch);
   EBUSY attempt must not suppress later completion checks; separate
   attempted from replay-complete; publish-failure keeps descriptor pending
   and keeps admission closed; slot accounting should carry incarnation.

Invariant for the code comment: "Before a mount may read shared metadata or
transition to LIVE it must establish a stable recovery cut and ensure every
applicable dirty/dead slice preceding the cut is replay-complete. Pending /
claimed / in-progress does not satisfy this."

## Implementation notes
- Gate loop after rounds: sweep (WITHDRAWN-flag OR pending) non-local
  slots minus published; try acquire+replay; poll; RULE-0 bounded; timeout
  → fail mount (same spirit as the (b2) residue gate).
- Verify/reorder producer: where does fire_dead write the cert vs mark
  pending durable? (disklock.c fire_dead pipeline).
