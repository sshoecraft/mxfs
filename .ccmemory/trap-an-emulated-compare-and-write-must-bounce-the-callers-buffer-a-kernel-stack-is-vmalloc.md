---
name: trap-an-emulated-compare-and-write-must-bounce-the-callers-buffer-a-kernel-stack-is-vmalloc
description: TRAP (0.90.40): the DRBD CAS emulator wrote the caller's buffer via bio; mxfs_bootstrap_claim passes a stack image, kernel stacks are vmalloc'd → -EI…
metadata:
  type: feedback
tags: [drbd, pal, kernel]
---

SCSI COMPARE AND WRITE (`pal/linux/kern.c`) copies its compare and write images into a page of its own, so callers hand it anything. `mxfs_bootstrap_claim` passes `&want`, a stack variable.

The DRBD emulator (`pal/linux/drbd.c`) built its write bio straight on the caller's buffer. `mxfs_pal_bio_sync_bdev` refuses vmalloc memory with `-EINVAL`, and kernel stacks are vmalloc'd (`VMAP_STACK`). So the first stack-buffer caller, the pair-outage bootstrap claim, failed: `P-BOOT-CLAIM … rc=-22`. Normal operation never showed it, because the disklock and ledger callers pass heap buffers.

**Rule.** A software replacement for a device command must accept every buffer the device path accepts. Bounce through its own kmalloc'd memory, as the emulator now does.
