---
name: ccloop-c7ee71c6-sess48-STEP1-design-ex-grant-epoch-in-caw-slot
description: sess48 STEP-1 SHIPPED (0.11.395): ex_grant_epoch live in mxfs_caw_lock_slot, stamped in caw_grant_epoch_update; next = pag plumbing + CIL-drain audit…
metadata:
  type: project
---

# Foreign-replay token campaign — step 1 SHIPPED (0.11.395, srcver 208BAA18)

## What shipped
- `dlm/dlm_caw.h` struct mxfs_caw_lock_slot: `uint64_t ex_grant_epoch;` (took 8 of reserved[352]→[344], after open_holders, 512B assert intact, big comment block documents semantics).
- `dlm/dlm_caw.c caw_grant_epoch_update` (~line 945): stamps `s->ex_grant_epoch = s->generation` whenever mode is EX/PW — the ONE helper every grant path already calls AFTER its generation bump (verified: initial acquire ~4268, waiter-promote ~2826, convert-upgrade ~5928, batch fresh ~7195 [generation=1 pre-stamp ⇒ epoch≥1] and batch existing ~7223, claim-recycle ~3503 [generation preserved via tombstone/caw_claim_inherit_epoch]). Downgrades correctly do NOT stamp (exclusive interval ends; validity requires holder bit).
- 0 = no-authority sentinel: fresh pre-grant, tombstoned (caw_tombstone_slot memsets — fine, fully released), REPAIRED slots (P-H22-REPAIR reconstructs from zero — deliberate: unknown EX history ⇒ replay must fail closed for that AG; do NOT "preserve" a possibly-garbage epoch).
- Deployed 32/caw, guards clean (matrix 9/9, reap CLEAN), soak cycle 395-c1 clean (agpurge-alive=61, all fatal signals zero). Passive field — no consumer yet.
- CHANGELOG 395 entry written.

## Next micro-steps (order per GPT ruling memory ...-GPT-ruling-foreign-replay-token-design)
1. **Grantee plumbing**: expose the granted epoch to the kernel mount — either out-param through mxfs_dlm_caw_lock→v5 (`mxfs_v5_dlm_ag_lock`) or reuse the existing readback idiom (`mxfs_dlm_caw_read_generation` precedent at v5_mount.c:2987 reads slot fields post-grant; a sibling `mxfs_dlm_caw_read_ex_grant_epoch` is ~20 lines). Store in `pag->pag_mxfs_grant_epoch` at AG EX acquire (set where xfs-side caches the AG grant — the pag_dlm_cached machinery in xfs_mxfs_dlm.c).
2. **CIL-drain-at-release audit**: does bast_work_fn Phase 2 (drain_meta/alloc/inode_buffers + blkdev_flush) guarantee the AG's CIL items are FORMATTED AND STABLE before mxfs_v5_dlm_ag_unlock? Likely needs xlog_cil_force(+wait) before the drain, else G1-dirtied buffers relogged under G2 misattribute (the ruling's non-negotiable). Audit first, measure, then add.
3. **blf v2 token** (+log-incompat flag): {version, resource_class, resource_id, grant_epoch, owner_slot, owner_boot_epoch} after the blf bitmap, new blf_flags bit; writer reads pag_mxfs_grant_epoch at buffer logging/format time; replay-side parser.
4. **Recovery descriptor + IMAGE_REPLAY_DONE** rework of the P163 foreign-replay flow; freeze-victim-slots-until-DONE (mxfs_dlm_caw_purge_node at v5_mount.c:1197/1274 must not clear victim EX bits pre-DONE).
5. Replace P223 untagged-skip with the exact-match token gate; A/B via tests/foreign_replay_ab.sh + the 5-point fault injection (sess32 ruling).

## Standing soak
0.11.395 = 394 + passive field; fossil-arm tripwires ride every cycle (11 clean cycles across 394/395). Criteria: NO — 11 OPEN of 39 (4 critical).
