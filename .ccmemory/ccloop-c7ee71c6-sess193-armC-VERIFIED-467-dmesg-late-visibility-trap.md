---
name: ccloop-c7ee71c6-sess193-armC-VERIFIED-467-dmesg-late-visibility-trap
description: sess193: Arm C late slot-release VERIFIED on 0.11.467 (test32, ftrace-proven chain, P278 rc=0 ×2); sess192 fail = dmesg late-visibility artifact
metadata:
  type: project
---

# sess193 — Arm C verified; dmesg late-visibility trap identified

## Verdict
Arm C (sess180 ruling: defer HB-slot release until after xfs_unmountfs
writes the unmount record) WORKS. sess192's "first verify FAILED" was a
FALSE NEGATIVE.

## Evidence
- Build 0.11.467 sv 45C15DFCBE7578D9258D801 = 466 + P278 instrumentation
  (slot_release_commit entry/rc; release_slot EINVAL/EBUSY/READFAIL logs).
  Deployed to test32 only (NFS /src/mxfs/mxfs.ko, md5-verified on node
  after drop_caches).
- Clean umount cycles show: DLM shutdown complete → P30-QUIESCE (inside
  xfs_unmountfs) → "disklock: released heartbeat slot 13 (clean
  teardown)" → "P278-LATE-RELEASE unmount_clean=1 release rc=0"
  (5959.171312 and 6147.105694).
- ftrace func_stack_trace: mxfs_disklock_release_slot ←
  mxfs_v5_dlm_slot_release_commit ← xfs_fs_put_super ←
  generic_shutdown_super. Decisive.
- Retro: sess192's 466 umount at 5444.503600 DID have the release line —
  sess192 read dmesg too early.

## THE TRAP (applies to any umount-teardown verification)
The umount task's final printks are stamped with correct timestamps but
become VISIBLE to dmesg readers LATE — in one measured case a read
MINUTES after the umount still lacked the P278 line, and a later read
showed it with the original timestamp (printk record finalized late).
Rule: never conclude a teardown log line is absent from a single
immediate dmesg read; re-read later and grep the WHOLE ring.

## Rig facts
- Manual caw mounts: /dev/mapper/mpatha, never /dev/sda (multipathd
  holds sda → "Can't open blockdev"). run.sh:99.
- 467 (proto-gen unchanged) joins a 466 cluster fine — mixed srcversion
  is admitted; only proto-gen is gated (C7).
- test32 slot=13; rig left: 31 nodes mounted 466, test32 unmounted, 467
  loaded, ftrace tracer=nop.

## Open
- Dirty branch (P277-SLOT-RETAINED-UNMOUNT-DIRTY) not rig-exercised:
  needs forced-shutdown + umount fault test.
- Fleet still mixed: full prep to uniform build + full board 32/caw +
  vergate mixed_build arm before ledger work.
