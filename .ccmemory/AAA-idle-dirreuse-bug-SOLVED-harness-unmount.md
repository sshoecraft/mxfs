---
name: AAA-idle-dirreuse-bug-SOLVED-harness-unmount
description: SOLVED 2026-07-16: the "idle-trigger dir_reuse" 2/caw bug = tests/caw/dlm_lock_correctness.sh unmounting node1's live FS as last suite test. Harness…
metadata:
  type: project
tags: [dir_reuse_coherency, harness-bug, dlm_lock_correctness, root-cause, caw, multipath]
---

# The "idle-trigger dir_reuse_coherency" bug — SOLVED (harness, not kernel)

## Root cause (proven 2026-07-16, ccloop 8ba7ae5c sess1)
`tests/caw/dlm_lock_correctness.sh` line 16 did `mountpoint -q $MNT && umount $MNT`
before its SG_IO probes, and it runs as the LAST test of every caw rung
(coord=none → node1 only). So after every full caw suite: **test1's cluster FS was
silently unmounted**, module still loaded, `.cluster_marker.json` still claiming
"formed". Every subsequent same-formation (filtered/solo) test ran rank1 against
the **bare rootfs mountpoint directory** — invisible to peers. Proof: umount pid
586165 comm=umount at 13:56:12Z = the second dlm_lock_correctness's ssh session
opened; test1 statfs showed ext2/3; bare /mnt/shared held debris dating to Jun 15
(test2: 62 entries, test4: 38, test3: 25 — struck broadly for a month).

This explains EVERY state.md finding of the 2026-07-15 session: rank1 "sees only
its own 100 entries" (its local rootfs), rank2's coordinated lookups correctly
ENOENT (dir never existed on the shared FS), root inode on disk correctly
byte-identical across reloads (rank1 never wrote to the real FS), sticky until
reform, "full 19-test suite must run first" (the unmount IS the suite's last
step), fresh-reform+idle alone doesn't reproduce. **The 10-minute idle was a red
herring**; broken from the instant the suite ended. The 7 reverted kernel fix
attempts never could have worked. Also fixed: the test scribbled hardcoded LBA
83886080 (40GiB in = inside live XFS data area) while peers had it mounted.

## Fixes (all tools/harness — kernel srcversion 67AB53E622F5450D5BC8692 UNCHANGED)
1. `tests/caw/dlm_lock_correctness.sh`: never unmounts; scratch LBA derived at
   runtime = `disklock_offset/512 - 1` (last sector of the mkfs 4K-alignment gap
   below disklock — journal_size ≡ 4608 mod 4096 so the 3584B gap always exists;
   nothing ever reads it). Parses `chk_mxfs -v`; SKIPs if super unreadable
   (never writes a guessed LBA).
2. `tools/mkfs_mxfs.c`: explicitly zeroes + documents that scratch sector
   ("Step 3b", transport self-test reservation).
3. `run.sh run_coord`: PRE-ASSERT before every coordinated test launch — all N
   nodes must have the cluster FS mounted, else hard FAIL naming the node(s)
   ("a prior test broke cluster formation state"), before t0 so it never counts
   against RULE-0 budgets.
4. Bare-mountpoint debris swept on all 32 nodes (guarded `mountpoint -q ||`).
VERSION 0.10.104 → 0.10.105 (tools/harness only).

## Validation (all on mpatha, build 67AB53E622F5450D5BC8692)
- Fixed 2/caw full rung: 19/19 PASS (run 20260716T142731Z); both nodes STILL
  MOUNTED after (old harness: test1 always unmounted here).
- Solo dir_reuse immediately after suite: PASS 261s 145/145 (old: 100% FAIL).
- Solo dir_reuse after 600s idle: (validating at write time — the exact
  state.md recipe.)

## Reusable lessons
- When a multi-node test fails with "peer can't see anything", check
  `findmnt /mnt/shared` on EVERY node FIRST — statfs type ext2/3 = writing to
  bare rootfs. `stat` succeeding on the "shared" path proves nothing.
- Tests that need raw device access must never unmount the live cluster FS —
  SG_IO doesn't require it. Destructive raw writes only to the reserved scratch
  sector (disklock_offset - 512).
- The month of bare-dir debris means historic "mystery coherency FAILs" (esp.
  odd 16-node cells) may have been this poison; treat old FAIL cells with
  suspicion.
