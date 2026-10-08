---
name: technique-drbd-concurrent-writes-detected-names-two-hosts-writing-one-sector-map-it-with-chk-mxfs-geometry
description: DRBD 8.4 dual-primary logs 'Concurrent writes detected: local=<s>s +<len>' when both hosts write overlapping sectors in flight: a free oracle; it can…
metadata:
  type: reference
---

**What it is.** On an MXFS-on-DRBD pair, DRBD 8.4 (two-primaries) checks every peer write against its own in-flight writes. An overlap logs, on both hosts:

    drbd mxfs/0 drbd0: Concurrent writes detected: local=2757804s +6144, remote=2757803s +1024[, assuming remote came first]

`local`/`remote` are 512-byte sectors of /dev/drbd0 and byte lengths. For a correctly coordinated cluster FS this should never appear: a holder's write of a block must complete before the grant moves, so two hosts' writes of one sector can never be in flight together. One line is direct evidence that one host published bytes it held no write tenure for — no MXFS instrument, no knob, zero cost.

**It is also a stability bug on DRBD.** 0.90.92 nested pair, 2026-10-07: four conflicts in 5 s were followed on pve9-2 by `ASSERTION req->rq_state & RQ_NET_PENDING FAILED in __req_mod`, then `BAD! BarrierAck #51594 received, expected #51593!`, conn Connected -> ProtocolError, and participant 1 lost the tie-break and restarted itself. Record D-DRBD-BOTH-HOSTS-WRITE-ONE-DINODE-AT-ONCE-AND-DRBD-DROPS-THE-LINK.

**How to read a sector.**
- `chk_mxfs --geometry /dev/drbd0` is safe on a mounted host: gives `xfs_data_offset` (bytes), agblocks, agblklog, inopblog, blocksize, inodesize.
- XFS daddr = sector - xfs_data_offset/512. fsblock = daddr / (blocksize/512); agno = fsb / agblocks; agbno = fsb % agblocks.
- For a dinode: agino = (agbno << inopblog) + sector offset within the block (512-byte inodes); ino = (agno << (agblklog+inopblog)) | agino.
- Confirm by reading the sector raw (`dd if=/dev/drbd0 bs=512 skip=<s> count=1 iflag=direct | od -t x1 -N 16`): MXFS dinodes start `4d 4e` ("MN"), then di_mode.

**How to count it.** `journalctl -k -b <n> | grep -c 'Concurrent writes detected'` per boot on each host. A boot with zero is the baseline; the physical pair's pve2 had zero in 70 boots up to 0.90.92.

**What made it appear.** The shared-directory churn (tests/pve_churn_fairness.sh) under ftrace's function profiler (tests/pve_pair_profile.sh) on both nested hosts; the same churn unprofiled 4 min earlier logged none. Timing perturbation widens the race; a race only timing hides is still the defect.
