---
name: ccloop-c7ee71c6-sess48-STEP2a-SHIPPED-pag-grant-epoch
description: sess48 STEP-2a SHIPPED (0.11.396): pag->pag_mxfs_grant_epoch populated at fresh AG EX acquire via mxfs_v5_dlm_ag_grant_epoch; next = CIL-drain audit…
metadata:
  type: project
---

# Token campaign — step 2a SHIPPED (0.11.396, srcver 090AAB7D)

## What shipped
- `mxfs_dlm_caw_read_ex_grant_epoch(ctx, resource, *out)` in dlm/dlm_caw.c (+dlm_caw.h proto) — find_slot + read slot->ex_grant_epoch; 0 = no authority.
- `mxfs_v5_dlm_ag_grant_epoch(ctx, agno, *out)` in dlm/v5_mount.c (+v5_mount.h proto) — CAW only, TCP -ENODEV.
- `pag->pag_mxfs_grant_epoch` (uint64, xfs/libxfs/xfs_ag.h after pag_mxfs_inocl_wr_epoch, full comment) — populated in the FRESH-grant success path of the AG acquire in xfs_mxfs_dlm.c (~34572, inside the sess19b post-grant block that already reads slot generation: same slot-stable, pre-pag_dlm_lock window; assigned under pag_dlm_lock next to `pag_dlm_holders = 1`). Read failure ⇒ 0 ⇒ fail closed.
- Deployed 32/caw; prep+reap+matrix green; 396-c1 lap+sweep clean (all fossil-arm tripwires zero — 13 clean cycles across 394/395/396).

## Next (order per ...-GPT-ruling-foreign-replay-token-design)
1. **Step 2b — CIL-drain-at-release audit** (the ruling's non-negotiable): before mxfs_v5_dlm_ag_unlock, are the AG's CIL items FORMATTED AND STABLE? bast_work_fn Phase 2 drains delwri buffers + blkdev_flush, but a buffer dirtied under tenure G1 could still sit in the CIL un-formatted at release, get relogged under G2, and misattribute. Audit what Phase 2's drain guarantees w.r.t. the CIL (drain_meta_buffers implies prior xlog_cil_force? find it); if gap: add xlog_cil_force + wait scoped to release, measure release-latency delta (RULE 0), then ship.
2. **Step 3 — blf v2 token**: new blf_flags bit + trailing {version, class, resource_id, grant_epoch, owner_slot, owner_boot_epoch} after the blf bitmap; writer reads pag_mxfs_grant_epoch at buffer format time (CIL formatting happens per-checkpoint — the ruling's mixed-epoch caveat is why 2b comes first); log-incompat flag; recovery-side parse.
3. Step 4 — recovery descriptor + IMAGE_REPLAY_DONE rework of P163 flow; freeze victim slots until DONE (v5_mount.c:1197/1274 purge ordering).
4. Step 5 — token gate replaces P223 untagged-skip; foreign_replay_ab.sh A/B + 5-point fault injection.

## Criteria: NO — 11 OPEN of 39 (4 critical)
