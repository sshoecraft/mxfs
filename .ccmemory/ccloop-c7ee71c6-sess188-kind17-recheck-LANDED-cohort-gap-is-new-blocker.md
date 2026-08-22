---
name: ccloop-c7ee71c6-sess188-kind17-recheck-LANDED-cohort-gap-is-new-blocker
description: sess188: kind-17 recheck leg LANDED+rig-proven (sv B1A30F20, P227-SNLOCAL-ACCEPT fired, no P239); remount still FAILs — WITHDRAWN slot absent from 6.…
metadata:
  type: project
---

# sess188 — kind-17 exclusion-recheck landed; barrier-cohort gap is the next blocker

D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE, remount arm.

## Landed + rig-proven (sv B1A30F20B52117926DD8D92, test32 loop7)
Per sess188 GPT ruling (ccmemory ccloop-c7ee71c6-sess188-GPT-ruling-kind17-exclusion-recheck):
- disklock.{h,c}: mxfs_disklock_recovery_replay_authorized grew a
  `uint16_t *out_fence_kind` last param — set ONLY on rc==0, i.e. from a
  strict-validated descriptor that still matches the presented lease.
  External callers (v5_mount.c reacquire + complete-start) pass NULL.
- v5_mount.c v5_exclusion_recheck: kind-aware. One validated read inside the
  recheck yields tuple-match + kind. kind-17 leg = single_node_exclusive param
  AND mxfs_v5_dlm_is_single_node AND
  mxfs_disklock_lowest_live_slot(skip=local_slot) < 0 (identity, not count).
  Refusals: P239-AUTH-STALE (RBLK_OWNED_ELSEWHERE) / P239-SN-LAPSED (new
  MXFS_RBLK_SN_LAPSED=10). PR leg unchanged for other kinds; !scsipr
  early-out moved AFTER the kind-17 leg.
- Rig: race PASS, delay PASS; claim/lease now succeed (P238-RECOV-LEASE),
  replay ran, P227-SNLOCAL-ACCEPT applied the untagged txn, stage 2->3.
  local_slot was >=0 at the claim site — no false SN refusal.

## New blocker (log-proven)
"mount recovery barrier complete: cohort=0x0" with WITHDRAWN slot 0 present:
mxfs_v5_dlm_mount_recovery_cohort snapshots frozen ACTIVE peers only, so the
withdrawn dirty slice is recovered ASYNC (P233-MPHASE-DISPATCH) after the
mount is live. Marker is in the SHORTFORM ROOT DIR = root inode core; the
live mount cached the root inode before replay rewrote the inode cluster on
disk → stale in-core root → marker invisible (and write-back can clobber the
replayed image). Exactly sess184 ruling blocker 2(a).

## Fix path (next session)
sess185 already built mxfs_disklock_get_withdrawn_slots (disklock.c:5549).
Wire its mask into mxfs_v5_dlm_mount_recovery_cohort (v5_mount.c ~3398;
consumer xfs_mxfs_dlm.c:43596 todo-loop ~43662); skip freeze-confirm for
WITHDRAWN (voluntary death definitive, sess184 2a). Then rerun repro.

## Outstanding from sess188 ruling
- Join/admission interlock audit (req 4): joining node must refuse FS I/O
  while a claimed kind-17 recovery descriptor exists (sess58 item-6A gate).
- No-resume durability: kind-17 lapse blocked-state is in-memory only; same
  gap exists for PR lapses (pre-existing; noted, not new).
