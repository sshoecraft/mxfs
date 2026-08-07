---
name: ccloop-c7ee71c6-sess81-step5.1-implementation-start-point
description: sess81: the exact edit sites for step 5.1 (grant-state lifecycle + AG classification conjunction) — found and verified, ready to write.
metadata:
  type: reference
tags: [foreign-replay, authority-token, step5, sess81, implementation]
---

# step 5.1 — the exact edit sites (verified sess81, nothing written yet)

Companion to `ccloop-c7ee71c6-sess81-GPT-ruling-step5-scope-is-WRONG-false-apply`.
Nothing in this step changes replay behaviour; it is producer-side only, so it
is independently safe and needs no A/B to land.

## (a) Publish the epoch — ALREADY correct, leave it

`xfs/xfs_mxfs_dlm.c:34644` `pag->pag_mxfs_grant_epoch = grant_epoch;` — set
under `pag_dlm_lock`, in the slot-stable window right after the granting CAS,
alongside `pag_dlm_holders = 1` and the tenure bump. Failure of
`mxfs_v5_dlm_ag_grant_epoch()` already leaves 0 = fail closed. This satisfies
GPT's "publish only after the granting CAS succeeds".

## (b) CLEAR the epoch when release begins — the missing half

**`xfs/xfs_mxfs_dlm.c:38976` is the ONE site that sets
`pag->pag_dlm_demoting = true`** (grep-verified: single occurrence in the
tree). It sits in bast_work_fn Phase 2, under `pag_dlm_lock`, immediately
after `pag_dlm_cached = false`, and it is the COMMIT POINT of the release
decision — every flush / drain / `mxfs_v5_dlm_ag_unlock` happens after it.

Clearing `pag_mxfs_grant_epoch = 0` there (same lock, same critical section as
`demoting = true`) gives exactly GPT's required ordering: in-core authority is
invalidated BEFORE the disk unlock becomes visible, and the drain barrier that
follows guarantees no item can still be formatting with the old epoch by the
time the grant is transferable. Clearing at the unlock sites instead
(`:39289`, `:40849`, `:40951`) would leave the capture window GPT called out.

Fail-closed consequence: a transaction that commits after the demote decision
but before the drain completes gets `class=NONE` ⇒ taints ⇒ skipped. That is
the status quo behaviour for every transaction today, so it is not a
regression.

## (c) Classification conjunction at the fill site

`pal/linux/xfs_buf_item.c:341-404`. Today: `SB` if `b_ops == &xfs_sb_buf_ops`,
else `AG{xfs_daddr_to_agno(blf_blkno)}` whenever `pag_mxfs_grant_epoch != 0`.
Replace the else-branch with the conjunction: `b_ops` in an allowlist of
genuinely AG-authorized metadata ops (`xfs_agf_buf_ops`, `xfs_agi_buf_ops`,
`xfs_agfl_buf_ops`, `xfs_bnobt_buf_ops`, `xfs_cntbt_buf_ops`,
`xfs_inobt_buf_ops`, `xfs_finobt_buf_ops`, `xfs_rmapbt_buf_ops`,
`xfs_refcountbt_buf_ops`) **AND** `xfs_blft_from_flags(blfp)` agrees **AND**
the containing AG's epoch is nonzero. Everything else ⇒ `MXFS_AUTH_CLASS_NONE`.
`b_ops` must be the primary discriminator: `XFS_BLFT_BTREE_BUF` conflates AG
btrees with inode bmbt blocks.

BLFT is already set on `blfp->blf_flags` before format time (the callers use
`xfs_trans_buf_set_type`), so both halves of the conjunction are available in
`xfs_buf_item_format_segment` with no new plumbing.

## (d) The measurement that proves (A) — do it in the SAME build

Emit a counter/print for buffers where the OLD rule would have said
`class=AG` but the new conjunction says `NONE` (type not AG-authorized). That
is a direct measurement of how many tokens are mislabelled today, i.e. of the
false-APPLY exposure the ruling predicted from code reading alone. Run it
under `tests/openunlink_deaths.sh unlinker_death` (~4 min, deterministic
reproducer that produces a real foreign replay) and read `P227-TOKEN` /
`P227-TOKENSUM`.

## Rig state at the end of sess81

0.11.418, srcversion `412957C596B75E582F3F676`, deployed and mounted on the
fleet (test1/2/3 spot-checked). The full board has still NOT been run on
0.11.418.
