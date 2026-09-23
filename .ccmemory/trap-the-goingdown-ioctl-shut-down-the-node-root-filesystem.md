---
name: trap-the-goingdown-ioctl-shut-down-the-node-root-filesystem
description: TRAP (sess432): XFS_IOC_GOINGDOWN (0x8004587d) == EXT4_IOC_SHUTDOWN — vergate.sh issued it on /mnt/vgate after a FAILED loop mount and shut down test…
metadata:
  type: feedback
---

# The s419-s421 vergate mixed_build "ENOTCONN + root-fs EIO" was TWO harness bugs, not MXFS

Evidence: tests/evidence/20260828T081751Z_vergate_livecap_mixed_build/dmesg_live_test32.txt lines 23141-23152.

1. `mount -t mxfs /dev/loop7` refused: `P303-FENCECAP-NOCAPS` -> `CAW mount REFUSED (-95)` -> `MXFS DLM init failed` -> mount(2) ENOTCONN (xfs_super.c:3293). Since 0.15.0 (sess378) a device with no SCSI PR needs `mxfs.fence_capability_override=1`; `single_node_exclusive=1` does NOT waive it. vergate.sh predated that and never set the override.
2. The harness then ran its python: `fcntl.ioctl(open('/mnt/vgate'), 0x8004587d, 2)` unconditionally. /mnt/vgate was a plain dir on ext4 dm-0 (root). ext4 defines EXT4_IOC_SHUTDOWN with the SAME number -> `EXT4-fs (dm-0): shut down requested (2)` / `Aborting journal on device dm-0-8` -> root-fs EIO, ssh reset, node needed a power-cycle. This is why every post-mortem dmesg capture was empty.

Fix (sess432, tests/vergate.sh): set fence_capability_override=1 for the loop arms (restore 0 at teardown); the GOINGDOWN ioctl runs only after /proc/mounts shows /mnt/vgate type mxfs.

Rule for every harness: NEVER issue XFS_IOC_GOINGDOWN / any shutdown ioctl on a path without first proving the path is the mxfs mount you meant. The ioctl number is shared across filesystems.

After the fix the arm got past setup and exposed a REAL finding: the fresh 4-AG loop fs's first `mkdir` after 'Ending clean mount' fails `Allocated a known in-use inode 0x83!` (xfs_ialloc.c:3293 verify) -> forced shutdown. Instrumented in 0.39.10 (P-DIALLOC-VERIFY). See the sess432 transcript / ledger.
