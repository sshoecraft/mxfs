---
name: caw-FIX-DESIGN-dlm_scaling32-put-inode-gen-in-resource-id-offset
description: FIX DESIGN (implementable, untested-host-wedged) for dlm_scaling@32 epoch: put ip->i_generation into mxfs_resource_id.offset (unused for inode locks)…
metadata:
  type: project
---

## FIX DESIGN — dlm_scaling@32 epoch false-positive (ccloop 0d6e174d sess2, 2026-07-07, UNTESTED: host wedged)

Refines [[caw-HYPOTHESIS-dlm_scaling32-epoch-is-slot-aliasing-under-churn]] (root: mxfs_resource_id has no
generation → reused inode inherits prior incarnation's last_ex_slot in caw_claim_inherit_epoch → false
handoff → epoch++ → dir_priv_ex_skip disengages → FUA storm → fail+wedge). CLEANER than deep plumbing.

### THE ELEGANT FIX: make the inode GENERATION part of the CAW resource identity.
`struct mxfs_resource_id` (include/mxfs/mxfs_common.h:60): {volume, ino, offset, ag_number, type, pad}.
For INODE-type locks, `offset` (extent start block) and `ag_number` are UNUSED (0). Repurpose `offset` to
carry `ip->i_generation` for inode-type resources.
- Effect: FNV-1a hash (dlm_caw.c:169, hashes raw resource bytes) now includes the generation → a reused
  inode (same ino, NEW gen) hashes to a DIFFERENT slot than its prior incarnation → never lands on the old
  tombstone. Even if linear-probing lands on it, `caw_claim_inherit_epoch`'s `memcmp(&prev->resource,
  resource)` (dlm_caw.c:722) FAILS (offset/gen differs) → no inheritance → fresh epoch=0/last_ex_slot=NONE.
- Same incarnation (same ino, same gen) → same hash → finds its OWN tombstone → inherits correctly
  (preserves the LOAD-BEARING cross-node dir-coherence-across-idle-gap that caw_tombstone_slot protects).
- NO deep plumbing: set it at the resource-BUILD site(s) where `ip` (hence i_generation) is available.
  On-disk slot `resource` bytes change for inodes (offset was 0) but that's fine on a fresh FS; slot SIZE
  unchanged (offset already in the 32-byte struct) → Arch Invariant 2 layout safe.

### IMPLEMENTATION (next session — with host):
1. Find every site building an inode resource_id (grep `type = MXFS_LTYPE_INODE` / `.ino =` in
   xfs/xfs_mxfs_dlm.c + dlm/*; the primary is where mxfs_v5_dlm_inode_lock builds the resource). Set
   `resource.offset = ip->i_generation` for inode-type. i_generation must be stable+correct at lock time.
2. **Param-gate it** `caw_ino_gen_in_resource` (default 0 = 115CCA8C behavior). CRITICAL: this changes the
   slot HASH → ALL nodes MUST use the SAME setting (a mixed cluster computes different slots for the same
   inode = lock split-brain). So test by setting it uniformly on all nodes (MXFS_EXTRA_MODARGS applies to
   all). Default 0 keeps ship behavior; flip to 1 as default only after validation.
3. Verify i_generation is the same VALUE all nodes see for a given inode incarnation (it's on-disk di_gen,
   so yes — but confirm mxfs loads it before building the resource).
4. TEST: dlm_scaling@32 must PASS (private inodes keep valid_epoch=0 → skip engages → no FUA storm → rate
   >= floor, no node wedge). Regression: dlm_scaling@16, cache_coherency@16/@32, dir_reuse (all use the
   CAW inode slots + the dir-coherence inheritance). Watch for any lock split-brain (all nodes same param).

### ALTERNATIVE if #1 finds too many build sites / i_generation not available at lock time:
thread a `claiming_gen` param from mxfs_v5_dlm_inode_lock down to the 2 caw_claim_inherit_epoch sites
(dlm_caw.c:1947, 4424) + store gen in the slot's spare `pad2` (dlm_caw.h:105) at grant; compare gen there.
More plumbing, but doesn't change the hash (no cluster-uniformity constraint).

### Fixes both dlm_scaling@32 AND the 32-node node-WEDGE that caused the host iSCSI wedge
([[HOST-WEDGE-clyde-iscsi-cleanup-livelock-2026-07-07-needs-manual-reset]]).
