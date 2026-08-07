---
name: ccloop-c7ee71c6-sess97-grant-result-outparam-LANDED
description: sess97: the sess96-ruled CAS out-parameter is LANDED (0.11.430, builds clean, not wired at XFS) — struct mxfs_grant_result threaded out of all 6 gran…
metadata:
  type: reference
tags: [sess97, step5.3, authority-token, foreign-replay, D-FOREIGN-REPLAY-UNGATED-IMAGES]
---

# sess97 — step 5.3(b) grant-result out-parameter LANDED (0.11.430)

Build: **0.11.430**, `srcversion 0F32EFC182D9B3A77FD4954`, builds clean (only the tree's
pre-existing missing-prototype / `%ld` vs s64 / iomap warnings). **NOT deployed, NOT
rig-verified.** Rig still prepped at 0.11.427.

This is the piece the sess96 RULE-5 ruling made mandatory before anything else in the
producer half: the epoch must be threaded OUT of the granting CAS, never read back from a
cache. It is pure plumbing — no behavioural change, every existing caller passes NULL.

## What landed

**`include/mxfs/mxfs_dlm.h`** — `struct mxfs_grant_result {resource, grant_epoch,
generation, kind, mode, valid, reaffirm}` + `mxfs_grant_result_init()`. Carries the full
rationale (the EX→NL→EX counterexample) in the header comment so it cannot be re-litigated.
`kind` is the `enum mxfs_lock_type` of the BACKING slot, which is what makes the sess95
ICLUS class reconstructible with zero inference. `mode` is the mode THIS NODE HOLDS in the
captured image, never the requested mode.

**`dlm/dlm_caw.c`** — `caw_grant_result_fill(gres, resource, slot, held, reaffirm)` (just
below `caw_grant_epoch_update`). `valid` requires `held ∈ {EX,PW}` **and** a nonzero
`ex_grant_epoch`; a zero epoch is treated as a namespace restart (tombstone+reclaim does
not preserve the field) and refused. Filled at **all 6** grant paths:

| site | path | reaffirm |
|---|---|---|
| `caw_wait_for_grant` post-CAS | contended grant | no |
| claim-into-empty post-CAS | first claim / tombstone recycle | no |
| compat-add post-CAS | shared join **and PR→EX upgrade** | no |
| `mxfs_dlm_caw_convert` post-CAS | explicit convert | no |
| `our_mode == mode` early return | already held | **yes** |
| `our_mode >= mode` early return | higher mode subsumes | **yes** |

The two `reaffirm` sites are NOT the cache the ruling rejected. They fill from `cur_slot` —
one image that simultaneously shows our holder bit and the epoch of the tenure that set it,
read together. That is first-hand evidence; it is flagged separately only so a later ruling
can tighten policy without losing the measurement. **These two matter a lot in practice**:
MXFS deliberately caches CAW grants past the XFS-side mode (`i_dlm_mode = NL` while the slot
stays held), so a large share of inode re-acquires take an already-held path and would
otherwise have been permanently non-proving.

`mxfs_grant_result_init(gres)` runs at entry to `mxfs_dlm_caw_lock` / `mxfs_dlm_caw_convert`
and at every v5 entry point, so **every** failure path, the TCP transport (which has no
gres plumbing), and a NULL transport all leave the result non-proving.

**Signature changes** (all callers updated, NULL where no certificate is wanted):
`mxfs_dlm_caw_lock` +gres, `mxfs_dlm_caw_convert` +gres, static `caw_wait_for_grant` +gres,
`mxfs_v5_dlm_inode_lock` +gres, `mxfs_v5_dlm_inode_lock_retries` +gres,
`mxfs_v5_dlm_inode_lock_try` +gres, `mxfs_v5_dlm_iclus_lock` +gres.
Touched: `dlm/mount.c` (2 wrappers), `dlm/v5_mount.{c,h}`, `xfs/xfs_mxfs_dlm.c` (6),
`xfs/xfs_inode.c` (3, incl. the local `extern` decl at ~4453), `xfs/libxfs/xfs_ialloc.c` (1).
AG paths pass NULL — AG authority already has its own `pag_mxfs_grant_epoch` channel.

The two batch `caw_grant_epoch_update` sites (~7632/7660 in the old numbering) are inside
`mxfs_dlm_caw_flush_held_to_disk_orig`, which is `__maybe_unused` — **dead code, not wired,
correctly skipped.**

## Exactly what is next (ruled order, sess96)

1. **Authority state separate from `i_dlm_mode`** — `ip->i_mxfs_auth_state`
   (NONE / UNPUBLISHED_EX / DURABLE_EX / RELEASING) under `i_dlm_lock`. `i_dlm_mode == EX`
   cannot distinguish unpublished / durable / releasing / re-affirmed / rebacked.
2. **Release-begin revoke chokepoint** — `mxfs_inode_authority_begin_release_locked()`,
   hooked at release-BEGIN, NOT at the 11 `mode = NL` cleanup sites. Plus a per-inode
   `i_mxfs_auth_gen` bumped on every revoke.
3. **Install** — `mxfs_inode_authority_install_durable_ex_locked(ip, &gres, gen_snapshot)`.
   The stale-completion guard the ruling demanded is the gen snapshot, taken under
   `i_dlm_lock` BEFORE descending into the DLM and re-checked at install; it defeats the
   EX→NL→EX counterexample exactly where `mode > i_dlm_mode` does not. Also required at
   install: `!releasing`, routing matches `gres.kind`, not reclaiming/withdrawing,
   `gres.valid`, `gres.mode == EX`. Within one tenure take the MAX epoch (a convert
   legitimately advances it without a release).
   Acquire sites to snapshot+install at: `xfs/xfs_mxfs_dlm.c` ~26097/26101 (ilock_begin
   slow path → installs at ~28370/28634), ~29402 (try-slow → ~29418), ~43338 (iclus).
   Never mint at `grant_local_new` (~29525), `rearm_unpublished` (~29643), or the 3 mirror
   re-affirm sites (~25970, ~27601, ~27904).
4. Certificate struct + RCU pointer + format-time peek, then wire the sess96
   `mxfs_buf_derive_owner()` ladder (already landed, currently unused) into the producer's
   `else` arm in `pal/linux/xfs_buf_item.c` (~line 780, the `mxfs_tokcls_unknown` branch).
5. Still-open release blockers from sess96: uint32 epoch **wrap** policy (note: the
   tombstone path already restarts the namespace at 0 — reachable TODAY, not in 5 days,
   which is why `caw_grant_result_fill` refuses epoch 0), and **transaction/CIL tenure
   crossing**.
