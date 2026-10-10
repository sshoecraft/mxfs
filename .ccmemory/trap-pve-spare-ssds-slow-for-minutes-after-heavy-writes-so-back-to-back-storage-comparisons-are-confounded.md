---
name: trap-pve-spare-ssds-slow-for-minutes-after-heavy-writes-so-back-to-back-storage-comparisons-are-confounded
description: TRAP: pve1/pve2 sdb (Kingston SVP100S) stall ~1 s on flushes for minutes after heavy writes; the run measured later wins. TRIM + alternate legs.
metadata:
  type: feedback
---

**What bit (2026-10-09, 0.90.114, physical pair spare disks /dev/sdb, KINGSTON SVP100S fw 0202, 2011-era SATA SSDs, no native FUA, 512 B sectors).**

Storage comparisons run back to back on these disks read the order of the runs, not the storage:
- 7-build comparison: LVM-on-DRBD (run first, disks idle beforehand) 7/7 installed in 1410-1635 s; MXFS (run straight after LVM's ~25 GB of writes) 3/7 in 2730 s. Read as "MXFS 1.6-1.7x slower" — confounded.
- vmio matrix (xfs-1pri, xfs-2pri, then mxfs): MXFS measured last read 2-5x slower than XFS; the same MXFS test on a fresh filesystem earlier read 26.9 MiB/s, better than XFS.
- MXFS run 40 s after the build harness stopped its builds (packer deleting VM images on the same mount) read 5x worse than a clean one.

**The proof it is the disks:** tests/pve_small_write_stall.sh on the RAW DRBD device, no filesystem: four 60 s passes of the same writer stalled (gaps >= 250 ms in the disk's request stream, nearly all right after a cache flush, tests/pve_bio_census.py) 69%, 58%, 47%, 37% of the run in order — falling with time whatever ran beside it (a 512 B sync write/s, a 4 KiB one, nothing). The hypothesis that MXFS's 512-byte register writes caused the flush stalls was DISPROVED by the same run.

**How to apply.**
- Never compare two storages on these disks by running them one after the other. scripts/pve_build_compare.sh: each leg blkdiscards sdb on both hosts (TRIM works, discard_max 2 GiB), idles SETTLE_S, and legs alternate (mxfs lvm mxfs lvm) so drift shows as two same-storage legs disagreeing.
- A mean latency on these disks is dominated by ~1 s flush stalls hitting 0.1-4% of I/O; compare p50/p90 and the stall fraction, not the mean.
- Leave the pair idle before a measurement: nothing deleting large files on the same mount.
