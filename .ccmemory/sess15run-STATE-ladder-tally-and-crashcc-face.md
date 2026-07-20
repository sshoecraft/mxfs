---
name: sess15run-STATE-ladder-tally-and-crashcc-face
description: sess15 tally (build 3AD15DA9 = FIX-H3+P15I): 14/15 clean since H3. One 2/tcp crash_consistency face (inobt CRC read-fail, disk later valid) — P15I ar…
metadata:
  type: project
---

# sess15 running tally + the crash_consistency face

## Builds
- FIX-H3 = 3C674F70 (see sess15run-FIXH3-final-shape-and-validation-ladder).
- 3AD15DA9 = FIX-H3 + P15I probe (print-only delta: sector-CRC fingerprint on
  read-verify failure, pal/linux/xfs_buf.c __xfs_buf_ioend after verify_read).

## Tally since FIX-H3 (each row = full suite runs, all-PASS unless noted)
- 8/tcp: r14 r15 r16 r17 r18 (3C674F70), r19 (3AD15DA9) — 17/17 ×6
- 4/tcp: ×2 (3C674F70) — 17/17
- 2/tcp: r1 r2 (3C674F70) PASS, r3 (3C674F70) FAIL, r4 (3AD15DA9) PASS
- 1/tcp: ×2 (3C674F70) — 16/16
Total 15 runs, 14 clean. Criteria marker NOT written yet.

## The 2/tcp r3 face (only blemish; artifact /tmp/run_crash_consistency_20260705T010218Z)
crash_consistency (cold-reload durability test — umount/mount, NO node crash):
- test1 01:02:55: xfs_dinode_verify STRUCTURE fail ino=0xa00080 (REG,
  size=18, nextents=1); P-SFV-FAIL err=-117 disk_differs=0 = durably corrupt
  dinode on disk (valid CRC, illegal structure).
- test1 01:04:40: sequence P126-XFSAILD-SKIP-AGMETA agno=4 daddr=8372920
  ops=inobt in_ail=1 dirty=1 (staled a DIRTY IN-AIL inobt = discarded
  committed metadata — tension with sess43 invariant BB54A138!) →
  P91-FUA-SKIP-LOGGED same daddr → xfs_inobt_read_verify CRC error 74 →
  EIO shutdown → netpartition/tds inherited dead FS (0/2 cascade).
- POST-MORTEM RAW DISK (clyde /home/steve/disk.img, xfs_data_offset=
  100704256 from chk_mxfs): block at daddr 8372920 NOW has VALID CRC
  (calc==stored d12f8902), monotonic records, LSN cycle=1. First 128B are
  byte-identical to the failing image's dump → the failure was in the tail
  3.9KB: either (a) torn in-core page mix around the concurrent P126 staling,
  or (b) durable garbage later repaired by peer/unmount flush.
- P15I probe (build 3AD15DA9, capped 16) fingerprints each 512B sector on
  the next verify failure → offline compare vs platter names the sectors.
- SUSPECT #1 for the whole face: P126 staling in_ail=1 dirty=1 AG-meta
  (xfs_buf_item.c ~608). If it recurs with P15I evidence, the fix direction
  is refusing the discard when the buffer carries THIS node's committed-
  undrained mods (sess43 direction) — but beware sess23 lesson (suppression
  misfires were themselves a corruptor) and the log-tail-pinning tension.

## fdw own-data face: r11 node7, r12 node4 — NOT seen in any H3 run (7+).
Best theory: FIX-H/H2 collateral (blocked self-demote stranding a file-inode
grant mid-write). fence forensics live in tests/suite/fence_during_write.sh
(FDW-MISS/REREAD, healed= discriminator).
