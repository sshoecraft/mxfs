---
name: caw-HYPOTHESIS-dlm_scaling32-epoch-is-slot-aliasing-under-churn
description: ROOT CONFIRMED (code-level): dlm_scaling@32 epoch>0 = mxfs_resource_id has NO inode-generation field, so a REUSED inode matches the prior incarnation…
metadata:
  type: project
---

## ROOT CONFIRMED (code-level, host-wedged so UNTESTED) — dlm_scaling@32 epoch false-positive

Supersedes the "slot aliasing" framing (REFUTED below). ccloop 0d6e174d sess2, 2026-07-07.

### THE BUG (proven by reading the code — not a guess):
1. `struct mxfs_resource_id` (include/mxfs/mxfs_common.h:60-67) = {volume, ino, offset, ag_number, type,
   pad}. **NO inode generation.** So resource_id for inode N is byte-identical across free+realloc of N.
2. `caw_claim_inherit_epoch` (dlm_caw.c:717-726): inherits `dir_epoch` + `last_ex_slot` from a tombstone
   IFF `prev->magic==TOMBSTONE && memcmp(&prev->resource, resource)==0`. Cross-SLOT aliasing is correctly
   excluded (exact resource match) — so my earlier "slot aliasing" hypothesis is REFUTED. BUT the match
   is by {volume,ino,type} only → a REUSED inode (same ino, NEW generation, possibly last owned by a
   DIFFERENT node) matches the prior incarnation's tombstone.
3. `caw_tombstone_slot` (dlm_caw.c:694-708) preserves dir_epoch + last_ex_slot into the tombstone (this
   is LOAD-BEARING for genuine cross-node dir coherence across an idle gap — do NOT just zero it).
4. Epoch advance (dlm_caw.c:672-678): on EX claim, `handoff = (last_ex_slot!=NONE && last_ex_slot!=my_slot)
   → dir_epoch++`. So a reused inode that inherited a PEER's last_ex_slot sees a false handoff on the new
   owner's first EX → dir_epoch++ → i_dlm_dir_valid_epoch>0 (observed 8,5,32 @32) → dir_priv_ex_skip gate
   (`valid_epoch==0`) disengages → private-dir FUA storm → dlm_scaling rate<50/s floor + node WEDGE.
5. Why only at 32 (not 16): 32 nodes × 2000 create+unlink/node = ~64k inode lifecycles → cross-node inode
   REUSE is frequent → pervasive false epochs. At 16 it's rare enough that dlm_scaling passes 16/16 alone.

### THE FIX (next session — implement + TEST once host reset):
Generation-gate the epoch inheritance so it only fires for the SAME inode incarnation.
- Option B (surgical, preferred): store the inode generation in `struct mxfs_caw_lock_slot` (dlm_caw.h:92,
  512 bytes — check for a spare/pad field; it already holds dir_epoch + last_ex_slot). Plumb
  `ip->i_generation` (or di_gen) down through the inode CAW lock/claim path to caw_claim_inherit_epoch.
  Inherit epoch/last_ex_slot ONLY if `prev->inode_gen == claiming_gen`; else leave fresh (epoch=0,
  last_ex_slot=NONE). A genuine same-incarnation idle-gap re-claim (gen matches) still inherits (preserves
  the load-bearing cross-node coherence). A reused inode (gen differs) starts fresh → no false handoff.
- Option A (broader, riskier): add `generation` to mxfs_resource_id — but that changes fnv1a_hash inputs +
  the on-disk slot `resource` bytes (Arch Invariant 2 layout) + every resource comparison. Avoid unless B
  is infeasible.
- VALIDATE: dlm_scaling@32 should PASS (private inodes keep valid_epoch=0 → skip engages → no FUA storm).
  Regression-check dlm_scaling@16 + cache_coherency@16/@32 (the dir_priv_ex_skip gate's coherence users)
  + the cross-node dir-coherence-across-idle-gap case the tombstone-epoch inheritance protects.

### Also fixes the 32-node node-WEDGE (the FUA storm wedged nodes → mass-destroy → host iSCSI wedge). See
[[HOST-WEDGE-clyde-iscsi-cleanup-livelock-2026-07-07-needs-manual-reset]]
[[caw-CORRECTION-mkfs-DOES-zero-caw-slots-dlm_scaling-epoch-is-intrarun]].
