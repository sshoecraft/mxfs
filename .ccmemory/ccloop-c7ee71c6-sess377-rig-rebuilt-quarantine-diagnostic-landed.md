---
name: ccloop-c7ee71c6-sess377-rig-rebuilt-quarantine-diagnostic-landed
description: sess377: rig rebuilt to 32/32 after a host kernel bug killed 2 VMs; board green but policy cell; #376 patch item 1 + repair step 1 landed and rig-ver…
metadata:
  type: project
tags: [sess377, rig, defect-376, quarantine, chk_mxfs, board]
---

«sess377 — rig rebuilt, quarantine diagnostic + verdict reader landed»

## Rig: 32/32 restored WITHOUT rebooting clyde

Session started with 31/32 (test4 wedged) and lost test5 during the first prep.
Both were killed by clyde's HOST ext4/jbd2 memory corruption, NOT by MXFS — see
ccmemory `clyde-host-ext4-slab-corruption-kills-rig-nodes-sess377` for the
oops evidence (an iSCSI IQN string, "2004-10.", found in a page-cache
folio->private) and for the recovery procedure, which is now codified as
`tools/mxfs_revive_node.sh` (modes `self` and `donor`, ~3 min per node).
clyde still needs a manual reset + fsck by a human; oops count was 3 at session
start and did NOT grow during any board or test run — the trigger was a large
BUFFERED copy (kswapd), which is why the revive tool copies with O_DIRECT.

After the rebuild: `./run.sh 32 caw prep_cluster` 73s (budget 240s), all 32
converged. Re-ran the 9 node-fault-BLOCKED board rows and every one PASSED:
dlm_fairness 22s, dlm_membership 5s, scaling_curve 12s, dlm_scaling 20s,
rsync_paired 22s, crash_consistency 90s/90s (AT BUDGET — watch it),
dir_reuse_coherency 105s/120s, fence_during_write 21s, fault_netpartition 9s.
Board at 32/caw is now 27 PASS / 1 FAIL, the FAIL being the `open_defects`
policy cell. The 10 node-faults on the previous board were the broken rig, not
MXFS.

## Build

0.14.9 -> 0.14.10. Final module srcversion this session: 7D01081DA5AF3C6F5A4D0A2.
(Intermediate: C62A1D489FE01EBA100B301, 677451EB8294C3B6D159519.)

## Landed for D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376

1. `dlm/disklock.c hb_report_claim_exhausted()` — both claim paths now classify
   the whole heartbeat table when a claim finds no free slot. The old
   "Cluster is full; reformat with more slices (mkfs_mxfs -n)" message is gone:
   it was unfollowable at the 32-slice hard cap AND destructive (mkfs -f erases
   the verdict). Markers P300-CLAIM-EXHAUSTED / -QUARANTINE / -WITHDRAWN /
   -FULL / -OUTOFRANGE.
2. `chk_mxfs --show-quarantine` (-Q) — read-only, O_DIRECT, decodes
   mxfs_recov_desc + mxfs_recov_outcome with their real identity-bound CRCs and
   prints the whole verdict plus a stable 64-bit VERDICT DIGEST over
   {volume uuid, slot, the complete 512-byte guard sector}. Verified against the
   live slot-2 quarantine on the rig: digest 6D2B17DB2D26F20F, reason
   POLICY_REFUSED_COMPLETE, domain AG_MASK 0x4 = AG 2 (the injected mask),
   3 refused items, usable RW slices 31 of 32.
3. `chk_mxfs check_disklock()` bug fixed: it tested `hflags &
   MXFS_DISKLOCK_FLAG_ACTIVE` on a field that is an ENUM (1/2/3), so a
   quarantined slot (flags==3) was reported to the operator as a LIVE MEMBER.
4. New harness `tests/quarantine_admission.sh <N> <victim> [agmask]` — ruling
   test A. Requires a FULL table (slices == nodes), the inverse of
   closure_hb_slot_reuse.sh's precondition. PASS on the rig 2026-08-20T01:57Z.

## The audit finding that matters beyond this defect

`mxfs_disklock_guard_slot()` treats a BAD-MAGIC sector as GUARDABLE, and its
only caller `mxfs_unclaimed_bucket_scan()` (xfs/xfs_mxfs_dlm.c:46172) walks
`b < XFS_AGI_UNLINKED_BUCKETS` (64) using the AGI unlinked-BUCKET index AS the
disklock SLOT index. On an N-slice volume, buckets N..63 are never claimable by
a member, so they are always "unclaimed" and the sweep routinely takes a
transient RECOVERY_GUARD in slots N..63 BY DESIGN.

Therefore: **slots 32..63 are live protocol state, not spare capacity.** Parking
anything permanent there would make guard_slot() return -EBUSY forever and that
AGI unlinked bucket could never be swept — a permanent unlinked-inode leak.

And: **a RECOVERY_GUARD is two different things.** With a valid descriptor
(recov_desc_present() requires MXFS_RECOV_DESC_MAGIC in the body) it is a
recovery lease or a terminal verdict; with an all-zero body it is a transient
bucket-sweep guard. Anything counting "quarantines" must check the descriptor,
not the flag. Both new code paths were corrected for this, and the
OUT-OF-RANGE "format/protocol violation" label was narrowed to MEMBER-shaped
records (ACTIVE/WITHDRAWN) only.

AUDITED CLEAN: every in-tree descriptor reader goes through
recov_desc_present() / recov_desc_of() / recov_lease_covers_node(), all of which
require the descriptor magic — so no bucket-sweep guard can be mistaken for a
victim recovery descriptor today. No new defect filed on that arm.

Also audited (needed for the archive design): the KERNEL never writes the 4KB
mxfs envelope super — zero write sites in dlm/, pal/, xfs/. Only mkfs_mxfs
(fresh struct), chk_mxfs (read-modify-write) and resize_mxfs (whole struct read
at :797, rewrite at :1110) touch it, so `reserved[3988]` is a genuinely quiet
region.

Geometry measured on the rig volume: [super 4096] [journal 67109376 @4096]
[disklock 33587200 @67117056] [XFS data @100704256]. The disklock region is
exactly 64*512 + 65536*512 = 33587200 — ZERO slack.

## Rig state left for the next session

DO NOT re-prep without reading this. The rig is deliberately parked mid-defect:
31 nodes mounted, test30 unmounted (its admission is refused), and a REAL
terminal quarantine standing at heartbeat slot 2 (victim node 3510436867,
incarnation 2928541969495874252, digest 6D2B17DB2D26F20F). That is the exact
end-to-end test bed for the repair state machine — `prep_cluster` mkfs's and
destroys it.
