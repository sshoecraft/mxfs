---
name: trap-qnap-mkfs-zero-region-verify-fail-transient-right-after-fleet-unmount
description: TRAP (sess513): prep mkfs on the QNAP LUN failed once 'zero_region verify FAIL @67119616 byte 2560 = 0x4b' ~1 s after test1's clean unmount; PR clean…
metadata:
  type: feedback
tags: [rig, qnap, mkfs, trap, sess513]
---

# mkfs zero_region verify FAIL on the QNAP LUN, transient (sess513, 2026-09-05 04:05Z)

Chain s513b prep (`run.sh 2 tcp prep_cluster`) failed in 13 s:

    mkfs.mxfs: zero_region verify FAIL @67119616 byte 2560 = 0x4b (storage silently dropped writes ...)

Context: test2 had just shut its filesystem down (EDEADLK-NL livelock, 04:00:49) and
test1 unmounted cleanly at 04:05:03-04 (P304-RETIRE-PENDING-RELEASED, P278-LATE-RELEASE,
module unloaded). mkfs ran on the next second. `sg_persist -k/-r` from both nodes
afterwards: PR generation 0x1e5, NO keys, NO reservation — so this was NOT the
stale-PR-blocks-mkfs shape (compiled-scst-iscsi-infra-wedge-recovery). The rerun
(chain s513c, 04:06Z) prepped fine (44 s).

Offset 67119616 = 0x4001000 is inside the region zeroed by the tauth ledger
zero_region (tools/mkfs_mxfs.c:732) — a 4 KiB page 4096 bytes past a 64 MiB boundary.
One 0x4b byte at page offset 2560 looks like a ledger entry landing after the zero, or a
stale read from the QNAP target's cache of a page a node wrote moments earlier.

Not root-caused (one occurrence). If it recurs: capture the mkfs timestamps against
the last node's teardown lines, and dump the page (`dd` of that 4 KiB) before the
rerun overwrites it. Treat a second occurrence as a ledger-worthy rig defect (a
silently dropped or reordered write on the shared LUN is a data-integrity hazard for
every result on it).
