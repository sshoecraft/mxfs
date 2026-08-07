---
name: ccloop-c7ee71c6-sess98-authority-state-machine-LANDED
description: sess98: the durable-authority state machine is LANDED (0.11.431, builds clean, partly wired) + the PROVEN-COMPLETE mode-transition chokepoint that ma…
metadata:
  type: reference
tags: [sess98, step5.3, authority-token, foreign-replay, D-FOREIGN-REPLAY-UNGATED-IMAGES]
---

# sess98 — step 5.3(c) authority state machine LANDED (0.11.431)

Build **0.11.431**, `srcversion 42A1FFAADA25BAB1986B520`, builds clean (only the tree's
pre-existing `mxfs_dlmtr_dump` missing-prototype and `xfs_aops.c` unused-variable warnings).
**NOT deployed, NOT rig-verified.** Rig still prepped at 0.11.427.

This is ruled items (2) and (3) of the sess96 RULE-5 ruling.

## The structural finding that shaped it

Exhaustive, mechanically verified grep: **all 19 real `ip->i_dlm_mode = ...` stores in the
entire tree live in `xfs/xfs_mxfs_dlm.c`, and every single one is already wrapped in the

    { u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
      ip->i_dlm_mode = <new>;
      mxfs_dlmtr_rec(ip, dtr_om, dtr_os, __LINE__); }

idiom.** (The 3 other grep hits are prose in comments.) So `mxfs_dlmtr_rec` — previously a
watch-ino diagnostic ring — is a **proven-complete mode-transition chokepoint that already
receives the old mode**. The authority backstop now runs there, *before* the watch-ino early
return: any mode LOWERING revokes authority. That is a miss-proof revoke which does not
depend on an enumeration of release sites staying complete as the code evolves. The function
is no longer diagnostic-only and its comment says so.

Lock audit of those 19: 15 verified under `i_dlm_lock`; the remaining 4 are
`mxfs_dlm_evict` (runs after the last reference — no concurrent access) and
`mxfs_dlm_inode_init` (fresh allocation).

## What landed

**`xfs/xfs_inode.h`** — `MXFS_AUTH_{NONE,UNPUBLISHED_EX,DURABLE_EX,RELEASING}` and
`i_mxfs_auth_{state,kind,reaffirm,gen,resource,epoch,incarn,line}`, with the header comment
carrying the reason `i_dlm_mode == EX` cannot serve as proof.

**`xfs/xfs_mxfs_dlm.c`** — `mxfs_inode_authority_{revoke,begin_release,note_unpublished,
install_durable_ex}_locked` plus 11 `atomic64` population counters (install / advance /
revoke / relbegin / unpub / backstop, and six *refusal reasons* — the measurements the ruling
asked for). Fields initialised **first** in `mxfs_dlm_inode_init`: the xfs_inode cache is not
zeroing and the backstop would otherwise read garbage on a fresh allocation.

Two decisions worth keeping:

- **The gen bump in `revoke` is UNCONDITIONAL, even at `state == NONE`.** An acquire whose
  granting CAS has completed but which has not yet won `i_dlm_lock` leaves the state machine
  reading NONE while a *real* on-disk grant exists. A release inside that window must still
  invalidate the snapshot, or the late completion installs a dead epoch. Skipping the bump
  "because there is nothing to revoke" reopens exactly the ruling's counterexample.
- **Install does NOT bump the gen.** The gen is a *relinquishment* counter. Two concurrent
  acquires with no release between them are on the same tenure and both install legitimately
  (MAX epoch, because a convert advances the epoch with no release).

`install_durable_ex_locked` refuses on: `!gres->valid`, epoch 0, mode ∉ {EX,PW},
`gen != snapshot` (the stale-completion guard), state RELEASING, `i_dlm_unpublished`,
kind/routing mismatch, `XFS_IRECLAIM|XFS_IRECLAIMABLE`, shutdown.

**Wired:** `note_unpublished` at both local-EX sites (`grant_local_new`,
`rearm_unpublished`) and the backstop.
**Not wired** (both `__maybe_unused`): `begin_release_locked`, `install_durable_ex_locked`.

## NEW BLOCKER found while writing this

**RELEASING is sticky, so an ABORTED release leaves the inode PERMANENTLY non-proving.**
`P15-REL-ABORT` and its relatives bail out leaving `mode == EX`, so the inode never
re-acquires and never re-enters install — the exact forever-non-proving failure the sess96
ruling warned about, and a direct false-SKIP source (which is what makes this defect
critical).

Fix shape: a **re-affirm path** — one fresh slot read filled through
`caw_grant_result_fill` with `reaffirm=1` (the same provenance class sess97 already
accepted: a single image showing both our holder bit and the tenure's epoch), hung off the
existing throttled P108 held-verify clock `i_dlm_heldchk_j`, and installed when a fast-path
ilock finds `auth_state != MXFS_AUTH_DURABLE_EX`.

## Next, in order

1. Explicit `begin_release_locked` at the release-BEGIN sites. Enumerated set: the DEMOTING
   transitions (`xfs_mxfs_dlm.c` 18118 / 19359 / 19451 / 19594 / 19661 / 19744 / 27949 /
   29036 **pre-sess98-shift**, plus `mxfs_clayer/pinned_resource.c` 90 / 126); the
   per-inode → iclus **routing change** at ~26069 pre-shift (it keeps `mode == EX`, so the
   backstop cannot see it — this is the one hole the backstop does not cover);
   `mxfs_dlm_evict`; and the inactivation release at `xfs/xfs_inode.c` 5331 / 5334 / 5337.
   NB: line numbers in `xfs_mxfs_dlm.c` moved ~+200 this session — re-grep, don't trust them.
2. Gen snapshot + install at the 3 acquire sites (`~26097/26101`, `~29402`, `~43338`
   pre-shift).
3. The re-affirm path above (closes the aborted-release blocker).
4. Certificate copy-out + format-time peek, then wire `mxfs_buf_derive_owner()` into the
   `mxfs_tokcls_unknown` arm of `pal/linux/xfs_buf_item.c`.

Still-open release blockers from sess96 are unchanged: uint32 epoch **wrap** policy, and
**transaction/CIL tenure crossing**.
