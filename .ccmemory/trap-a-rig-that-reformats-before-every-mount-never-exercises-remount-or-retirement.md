---
name: trap-a-rig-that-reformats-before-every-mount-never-exercises-remount-or-retirement
description: TRAP (0.90.40 DRBD): every rig step ran mkfs before mounting, so a node that unmounted cleanly could never remount and nobody saw it for 2 sessions.
metadata:
  type: feedback
tags: [drbd, harness, retirement, remount]
---

**What happened.** On the new DRBD attachment, a clean unmount leaves the heartbeat slot RETIRE_PENDING with key 0. Only SCSI PR evidence could settle it, so:
- a remount of that node hung in admission (P-ADMIT-RETIRE-PENDING-HELD);
- a whole-cluster restart was refused (P304-RETIRE-UNKNOWN-STALLED).

Two sessions of death tests, suite runs and fio passed regardless, because `drbd_rig.sh mxfs` and `run.sh` prep both run mkfs before every mount. The slot table was always fresh.

**Rule.** When bringing up any new attachment, transport or retirement path, test these before calling it working:
- one node unmounting and remounting while its peer stays up, several cycles;
- every node unmounting cleanly, then a mount on the same filesystem without mkfs.

A board that preps by reformatting never reaches either.

**Where it is now covered:** `scripts/drbd_rig.sh remount-test` (cycles, a crash-cut record left by `dbg_cas_nocaw_ops` bit 32, and a whole-cluster restart).
