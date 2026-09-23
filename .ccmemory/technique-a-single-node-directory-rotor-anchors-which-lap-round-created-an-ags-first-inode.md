---
name: technique-a-single-node-directory-rotor-anchors-which-lap-round-created-an-ags-first-inode
description: TECHNIQUE (sess615, D-0957): with the platter gone, an AG's first inode was attributed to a specific harness round through the per-mount dir rotor, a…
metadata:
  type: feedback
tags: [D-0957, attribution, allocator, rotor, evidence, technique]
---

# Attributing an inode number to a lap round after the volume is gone

## The situation (sess615, D-0957)
A cold `chk_mxfs` found AG 4 agino 128 (ino 33554560) inobt-allocated with a
chunk-initialisation core (mode 0, changecount 0). The volume had been re-mkfs'd
dozens of times since; the only dmesg captured for the lap that found it started
after its own ring buffer had rotated. Four other laps ran on the volume between
the previous clean check and the failing one, and none of them saved dmesg with
the inode number in it.

## What made attribution possible
1. **agino 128 is the first inode of the first aligned chunk of an AG** on this
   geometry (512-byte inodes, 8-block chunk alignment, first chunk at agblock 16).
   A parent inode logged by another lap (`dp_ino=92274816` = AG 11 agino 128)
   confirmed it: a fresh directory in a fresh AG gets agino 128.
2. **In `xfs_ialloc.c` the directory AG is pinned to the node slot under
   multi-node membership and steps `(node_slot + m_agirotor++) % maxagi` only
   when the mount is single-node.** So during a sole-survivor phase every mkdir
   on the survivor advances the AG by exactly one — including a harness's
   `mkdir -p probe && rmdir probe` writability check, which costs a rotor step
   like any other directory. The rotor is per mount and survives across laps
   while the node stays mounted.
3. **Two anchors from a later lap** (round 1 parent = AG 11, round 3 parent =
   AG 13, both logged by P-CR3-CANCEL lines in that lap's round files) fixed
   the stepping, and counting mkdirs backwards through both laps' sequences
   (rounds, the sole-phase probe mkdir; the pre-departure aging mkdir is pinned,
   not rotored) put the earlier lap's round 3 directory in AG 4 — a knob=1
   round of the partial-write-filter-without-grants arm.

## Rules that fall out
- **Count every mkdir, including probes and rmdir'd scratch dirs**, when
  walking a rotor. Miss one and the attribution lands on the wrong round.
- The pinned-vs-rotored switch means the rotor walk is valid only across
  the single-node/sole-survivor span; a multi-node mkdir does not step it.
- Record the assumption ("one mkdir per round, one probe mkdir per sole
  phase") next to the conclusion; it is an inference, not a platter read.
- A harness that toggles a knob per round and lets a later round's flush land
  an earlier round's dropped image (co-resident whole write) will strand
  FEWER objects than the number of knob=1 rounds; one stranded directory out
  of three knob=1 rounds is the expected shape, not evidence of a different
  cause.
