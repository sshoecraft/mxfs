---
name: trap-a-refused-mounts-command-return-time-includes-its-unwinds-cluster-acquires
description: TRAP (sess591, D-0960): the stall arm timed a refused mount by its command's return, which included the unwind's SB summary cluster lock (70 s wait);…
metadata:
  type: feedback
tags: [trap, harness, mount, unwind, sb-summary, D-0960]
---

# A refused mount's command return time includes its unwind's cluster acquires

**What happened (sess590/591, D-0960 stall arm of tests/join_during_takeover.sh):**
the harness ran B's `mount` synchronously and scored "the refusal returned inside
120 s" from the command's wall time. The refusal itself was logged at 52 s
("Failed to read root inode 0x80, error 78 — refused"), but the command returned
only after ~120 s, and the lap read as FAIL on every iteration although the fix
had done exactly what it should.

**Why:** a refused mount unwinds through `xfs_log_mount_cancel → xfs_log_unmount →
xfs_log_clean → xfs_log_quiesce`, and MXFS's quiesce took the SB summary cover
under its cluster lock (`mxfs_sb_summary_key`, ino 754974721 on the 24-AG rig
LUN) — a plain, non-fallible inode acquire whose page was itself in the
authority transition the mount had just been refused for. The unwind parked
there until the paused takeover moved again. (0.84.5 now skips the cover for a
mount that never set `m_mxfs_mount_complete`: `P960-REFUSED-MOUNT-NOCOVER`.)

**The lesson:** a mount command's wall time conflates three things — the
acquire under test, the refusal, and the unwind's own cluster work. A harness
that asserts on a refusal must (1) issue the mount detached, (2) time the
refusal by its dmesg line, and (3) time the command's return separately, with
its own bound, because the unwind is where the NEXT non-fallible acquire hides.
The same applies to any "operation refused" measurement whose failure path
tears down cluster state (unmount, freeze, remount-ro).

**Corollary for the D-0959 join path:** the bootstrap's join install freezes
its superblock, and that freeze's quiesce takes the same summary lock — so with
`dl_no_ondemand_takeover=1` the two-node view install waits for the pass to reach
the summary key's page, and B-mastered FREEZE_REQs are answered DEFER
(`my_view=0x0/0`) until then. Under a paused pass that is the whole pass.
