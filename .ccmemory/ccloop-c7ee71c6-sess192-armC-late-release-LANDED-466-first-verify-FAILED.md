---
name: ccloop-c7ee71c6-sess192-armC-late-release-LANDED-466-first-verify-FAILED
description: sess192: Arm C late slot-release LANDED (0.11.466 sv FB2A4097, deployed 32/caw) but FIRST VERIFY FAILED — clean umount logs no release/P277; instrume…
metadata:
  type: project
---

# sess192 — dirty-slice Fix 2 Arm C landed, verification open

## What landed (0.11.466, sv FB2A4097612E407EDCB0535, deployed 32/caw)
Per sess180 ruling item 4: clean-umount HB slot zero deferred until after
the unmount record is durable.
- dlm/v5_mount.h: struct mxfs_v5_dlm_slot_release {disklock, dev} +
  mxfs_v5_dlm_shutdown_defer_release() + mxfs_v5_dlm_slot_release_commit().
- dlm/v5_mount.c: mxfs_v5_dlm_shutdown = wrapper(late=NULL). In the
  disklock block: depart_clean && late → transfer disklock + ctx->dev
  ownership into late (skip release+destroy+dev-close in shutdown);
  commit zeroes iff unmount_clean else P277-SLOT-RETAINED-UNMOUNT-DIRTY,
  then destroy + close dev clone.
- pal/linux/xfs_super.c: put_super and fill_super out_unmount both call
  defer + commit(&late, !xfs_is_shutdown(mp)) right after xfs_unmountfs.
  Gate soundness: unmount record iclog forced PREFLUSH|FUA
  (xfs_log.c:1011/1143); record I/O error → xlog_force_shutdown →
  xfs_set_shutdown(mp). Reserve-failure edge benign (AIL fully pushed
  pre-record). Slot write still under live PR registration in put_super.

## Design facts
- disklock BORROWS v5 ctx->dev (no own clone) → ownership must travel.
- mxfs_journal_release_slot is MEMORY-ONLY; HB slot = sole on-disk
  consumability authority; Arm C scope = HB slot only.
- make clean deletes tools/* binaries — rerun `make tools` before prep.

## FIRST VERIFY FAILED (open, RULE 4)
Clean umount of test32 on 0.11.466: dmesg shows DLM shutdown complete →
P140/P30 (inside unmountfs) then NOTHING — no "released heartbeat slot",
no P277/P236/P259. Old-module baseline DOES print the release line.
test1 beacon still active_count=32 (maybe stale). Suspects: release_slot
silent early returns (-EINVAL !dev/slot<0; -EBUSY running; silent
bdev_read_prio failure) or late struct unfilled (needs withdrawn=true —
unlikely; P-GOODBYE absence proves nothing on CAW).
NEXT: instrument commit with unconditional P278-LATE-RELEASE rc log +
make release_slot early returns log; single-node cycle on test32.
Rig: 31 mounted on 466; test32 unmounted, slot likely still ACTIVE
(fail-closed; peers may evict it — harmless).
