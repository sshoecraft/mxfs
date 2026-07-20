---
name: caw-dlm_scaling-fix-BEST-approach-invalidate-caw-epoch-at-inode-dealloc-GFS2-pattern
description: BEST dlm_scaling fix approach (GFS2-validated): clear the CAW slot epoch/last_ex_slot at inode DEALLOC (not release), where mxfs has ip locally — sin…
metadata:
  type: project
---

## dlm_scaling@32 fix — BEST approach (GFS2-validated, ccloop 0d6e174d sess2, UNTESTED host-wedged)

SUPERSEDES [[caw-FIX-DESIGN-dlm_scaling32-put-inode-gen-in-resource-id-offset]] (resource_id-hash =
FAIL-CORRUPT, see [[caw-dlm_scaling-fix-CONSTRAINT-mixed-ino-callers-hash-consistency]]) and the slot-pad2
alt. This is cleaner, single-site, and matches a proven upstream design.

### The GFS2 precedent (read ~/src/linux/fs/gfs2, 2026-07-07):
GFS2's inode identity = no_addr (disk block, ~= mxfs ino) + **no_formal_ino (a generation)**.
- `gfs2_inode_lookup(sb, type, no_addr, no_formal_ino)` returns **-ESTALE** if no_formal_ino mismatches the
  on-disk inode (inode.c:120-121,187) → a REUSED inode (same block, new gen) is detected as stale.
- On dealloc (super.c:1331): `gfs2_inode_remember_delete(gl, ip->i_no_formal_ino)` RECORDS the deletion on
  the glock; `gfs2_inode_already_deleted(gl, no_formal_ino)` (super.c:1261) checks it. So GFS2 explicitly
  distinguishes an inode FREE from an idle release, and invalidates stale lock state at the FREE.

### THE FIX for mxfs (the exact analog):
The mxfs bug (root: [[caw-HYPOTHESIS-dlm_scaling32-epoch-is-slot-aliasing-under-churn]]) is that
caw_tombstone_slot (dlm_caw.c:694) PRESERVES dir_epoch/last_ex_slot across ALL releases — correct for an
IDLE-GAP release (same incarnation re-claims), WRONG for an inode DEALLOC (a different node/incarnation
reuses the ino → false handoff → epoch++). GFS2 shows the fix: treat FREE differently from release.
- **At inode DEALLOC** (mxfs's inode-free/inactivate hook — the XFS xfs_ifree / xfs_inactive path, where
  `ip` IS in hand → single site, NO lock-path plumbing, NO hash change, NO mixed-caller trap), issue a CAW
  slot op that CLEARS that ino's slot epoch: dir_epoch=0, last_ex_slot=NONE (or fully removes the slot so a
  realloc starts clean). Add `mxfs_dlm_caw_invalidate_epoch(ctx, resource)` in dlm_caw.c (write_slot with
  dir_epoch=0/last_ex_slot=NONE, or convert to a fresh/empty slot). Call it from the mxfs dealloc hook.
- Cross-node correctness: XFS inobt coordination ensures node A's free (incl. this invalidation) commits
  before node B can allocate that ino (B reads the free inobt) → B claims a clean slot → no false handoff.
- Cost: one extra CAW slot-write per inode FREE. dlm_scaling does 2000 unlinks/node, but this PREVENTS the
  ~5860 FUA-read storm/node → large net win. Frees already do AG-meta CAW ops; one more slot write is marginal.

### IMPLEMENTATION (next session, with host):
1. Find the mxfs inode-free/inactivate hook (grep xfs_ifree / xfs_inactive / xfs_inode_item free path +
   any existing mxfs hook; also xfs_dialloc's counterpart). Confirm `ip` + the dlm ctx are reachable there.
2. Add `mxfs_dlm_caw_invalidate_epoch(ctx, &resource)` (dlm_caw.c) — clears dir_epoch/last_ex_slot for the
   ino's slot (CAS-safe; if not found, no-op). Param-gate `caw_epoch_free_reset` (default 0) for A/B.
3. Validate: `scripts/dlm_scaling_diag.sh 32 "caw_epoch_free_reset=1"` → op-rate clears 50/s floor + FUA
   read-IOPS drops (skip re-engaged); dmesg shows private subdirs valid_epoch=0; no node wedge. Regression:
   dlm_scaling@16, cache_coherency@16/@32, dir_reuse (uses CAW inode slots + the idle-gap epoch inheritance
   — this fix must NOT clear epoch on an idle RELEASE, only on a FREE, so the idle-gap coherence is preserved).
4. This is FAIL-SAFE (default off) and CANNOT cause lock incoherence (no hash change; only clears epoch
   metadata on a genuine free).
