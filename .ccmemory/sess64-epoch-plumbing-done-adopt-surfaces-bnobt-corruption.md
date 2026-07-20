---
name: sess64-epoch-plumbing-done-adopt-surfaces-bnobt-corruption
description: sess64: monotonic dir-epoch DLM plumbing DONE+harmless (build 22F1D7BE). Epoch adopt trigger surfaces deep bnobt double-free corruption; disabled (ob…
metadata:
  type: project
---

## sess64 — per-dir monotonic epoch IMPLEMENTED (plumbing), but enabling the adopt surfaces a deeper bnobt-corruption bug

### Build 22F1D7BE (current on disk) = 5E78DEE0 baseline + epoch plumbing + epoch ADOPT DISABLED (observe-only P64-EPOCH-OBS). Behaves == baseline: 4/tcp dir_reuse = 2 dirent-loss rounds, **shutdown=0**.

### DLM epoch plumbing (DONE, harmless, KEEP — reusable next session)
- `dlm.h` struct mxfs_lock: +`uint32_t dir_epoch`. `mxfs_dlm.h` wire struct mxfs_dlm_lock_resp: +`uint32_t dir_epoch` (all nodes rebuild together → safe to grow wire).
- `dlm.c` dg_shadow_ent: +`uint32_t epoch`; `dg_grant_ex(...,uint32_t *epoch_out)` bumps epoch on every cross-node handoff (handoff==true), returns it. ALL call sites updated (1229 local, 3× wk-grant 1613/1972/3173, reaffirm 2672, upgrade 2714, remote-immediate 2870; deny sites pass 0). `send_grant(...,uint32_t dir_epoch)`. `process_remote_grant(...,uint32_t dir_epoch)` stores lk->dir_epoch (monotonic max). New query `mxfs_dlm_grant_dir_epoch()` + bridge `mxfs_v5_dlm_inode_dir_epoch()` (v5_mount.c/.h). Both grant-recv callers (mount.c:487, v5_mount.c:217) pass resp->dir_epoch.
- xfs_inode.h: +`i_dlm_dir_valid_epoch` (init 0 at xfs_mxfs_dlm.c ~11617). reload_inode computes `dir_grant_epoch` and advances valid_epoch at the adopt.
- Removed the dead P64-SHADOW-EVICT probe; P64-MASTER-HANDOFF now logs epoch.

### KEY EVIDENCE (RULE 4)
- P64-EPOCH-OBS fires 21-25×/node, **EXCLUSIVELY post_release=1** (the slow-path acquire reload at xfs_mxfs_dlm.c:10432). So genuine cross-node handoffs ARE caught on the slow path — the slow-path reload is the right adopt site.
- Master computes ~270 handoffs, grantee edge-bit P63-HANDOFF acts on ~58 (80% lost). The monotonic epoch closes that (level-triggered).
- BUT enabling the epoch ADOPT (genuine_handoff=true on epoch>valid):
  - ungated (build 1035BDC5): adopted on post_release=0 FASTEX path too → `xfs_create`/`xfs_dabuf_map HOLE` → trans_cancel corruption shutdown (1 round). [post_release=0 adopt rolls back in-flight mods / rebuilds extent map onto freed block — sess54 warning.]
  - gated post_release=1 (build 8E168717): STILL shut down — `bno+len>gtbno xfs_alloc.c:2428 xfs_free_ag_extent` = **bnobt DOUBLE-FREE** during rm-rf (3×). The disk-superset adopt, done MORE often (catching the 80%), surfaces a latent **adopt-vs-in-core-AG-free-state inconsistency**: the reload adopts a disk inode extent map inconsistent with the in-core bnobt/cntbt, so the subsequent rm-rf frees the wrong/overlapping extents → corruption. This is the sess42-47 bnobt double-free family, now coupled to the dirent-coherence fix.

### CONCLUSION / NEXT STEPS
The dirent-loss fix (epoch-driven disk-superset adopt) and the bnobt-double-free fix are COUPLED — you cannot land the adopt until the adopt is consistent with AG free-space state. Two directions:
1. **Make the slow-path post_release adopt AG-consistent**: when reload adopts a fresh disk extent map for a dir, the in-core AG bnobt/cntbt for that dir's blocks must ALSO be re-read/invalidated so a later free matches disk. (Investigate mxfs_dir_evict_bmbt_blocks + AG-meta drain coordination at adopt.)
2. **GPT design (preferred long-term)**: don't adopt in-place on the fast path; on stale epoch DISABLE the fast-path serve → force a clean slow-path NL→EX re-acquire (post_release=true) that reloads the WHOLE coherent set (dinode + dir blocks + AG meta) atomically. See [[sess64-GPT-design-per-dir-monotonic-epoch-replaces-handoff]].
3. Separately, dir_reuse 4/tcp baseline ALSO occasionally hits bnobt/dabuf corruption independent of dirent loss — there are ≥2 failure modes (single-dirent loss + AG-free corruption under rm-rf reuse) that BOTH must be fixed for 100%.

### MUST VERIFY: 2/tcp 17/17 not regressed by the DLM wire/plumbing change (in progress). 1/tcp 16/16 too. If regressed, the wire-struct growth or grant-path epoch is implicated → revert plumbing.</body>
