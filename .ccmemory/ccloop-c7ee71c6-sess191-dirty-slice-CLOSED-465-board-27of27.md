---
name: ccloop-c7ee71c6-sess191-dirty-slice-CLOSED-465-board-27of27
description: sess191: D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE CLOSED FIXED+VERIFIED on 0.11.465 (sv 4DB2D8A8); repro 3/3 arms PASS, vergate mixed_build PASS,…
metadata:
  type: project
---

# sess191 — dirty-slice defect closed; 0.11.465 board-green

## What closed
D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE (critical) — FIXED AND VERIFIED,
closure build 0.11.465 sv 4DB2D8A8247E6DF80AE6F2F, all 32 nodes deployed.

## Verification evidence (all this session, on the rig)
1. `tests/dirty_slice_release_repro.sh test32 all` — race, delay, remount arms
   ALL PASS in 8.8s (<60s budget). Remount chain: P274-CLAIM-WITHDRAWN-SKIP →
   P236-FENCE-CERTIFIED kind=SINGLE_NODE_EXCLUSIVE → recovery lease → foreign
   replay P227-SNLOCAL-ACCEPT → barrier "cohort=0x0 late=0x1 replayed=1",
   marker survived.
2. `tests/vergate.sh test32 mixed_build` — the discovering criterion — PASS
   (refuse=1 line, recovery=0 lines, file=1 content-checked).
3. FULL BOARD 32/caw: 27/27 PASS (open_defects red by policy). Prep+converge
   72s — no mount-time regression from the sess190 admission sweep.

## Harness fixes landed in tests/vergate.sh (sess191)
- mixed_build arm sets single_node_exclusive=1 for the WHOLE arm (host-private
  loop device: operator assertion true; victim needs the write-time snlocal
  marker at claim, and MB3's fence needs the assertion to certify). Reset to 0
  before remounting the shared LUN.
- ALL dmesg tags now unique per run (VG-*-$RUN): the ring buffer keeps prior
  runs' tags and sed anchors on the FIRST match — a stale first-run tag made
  MB2 count 18 phantom 'recovery' lines.
- marker check is content-based (grep B4-mixed-build), and arm setup clears
  stale /mnt/vgate/b4/marker residue from the node ROOT fs (pre-sess187
  unguarded-GOINGDOWN fossil; found one with B4-dirty-slice content predating
  test32's current boot).

## Behavior note (intended, per sess189 ruling)
A mount over a dirty descriptor-bearing slice that cannot be fence-certified
now FAILS -EBUSY after a 30s admission wait (observed live: loop dev, no PR,
single_node_exclusive=0 → P238-FENCE-UNPROVEN → rounds refused → -EBUSY at
~47s total). Diagnostic signature to recognize: mount(2) "already mounted or
mount point busy".

## Next (in order)
1. Fix 2 Arm C: HB slot release ordering after xfs_unmountfs (sess184 2b).
2. Join interlock audit (sess188 req 4).
3. #14 D-MIXED-VERSION-UNGATED-REPLAY B2/B3/B4; proto-gen 3→4 LAST.
Ledger: 27 open of 71 (16 critical).
