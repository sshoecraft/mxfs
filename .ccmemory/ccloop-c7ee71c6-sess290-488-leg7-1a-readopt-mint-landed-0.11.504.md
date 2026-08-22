---
name: ccloop-c7ee71c6-sess290-488-leg7-1a-readopt-mint-landed-0.11.504
description: sess290: D-488 leg7 part 1a LANDED+BUILT 0.11.504 sv 96F7DBC45AEA30D203219F7 — attested reaffirm guard + P294 READOPT mint in CAW already-held path;…
metadata:
  type: project
tags: [D-488, readopt-mint, P294, 0.11.504, leg7]
---

# sess290 — D-488 leg 7 ruling part 1a landed

Build 0.11.504 sv 96F7DBC45AEA30D203219F7 (incremental; clean rebuild
before deploy — .c+.h multi-file change).

## What landed
Implements sess289 ruling 1a (memory ...sess289-GPT-ruling-488-legs7-8...):

- `caw_lock_body` gains `(bool attested, uint64_t local_epoch)`.
  New public `mxfs_dlm_caw_lock_attested()`; old `mxfs_dlm_caw_lock()`
  delegates unattested → zero behavior change for every non-AG caller.
- Already-held EXACT-MODE arm (dlm_caw.c, inserted after the
  lreq_clr_still_good gate): when attested && mxfs_mode_can_write(our_mode)
  && !ctx->mount_adopt_window && local_epoch != cur_slot->ex_grant_epoch:
  - local_epoch != 0 → P294-REAFFIRM-EPOCH-MISMATCH, rc=-ESTALE (fail
    closed; local belief diverged from slot — should be impossible).
  - local_epoch == 0 → READOPT MINT: new image = cur with generation++,
    last_modified_ms, last_ex_slot=ctx->node_slot, ex_grant_epoch =
    caw_next_grant_epoch(Eold); real CAS via caw_slot(). -EAGAIN → outer
    retry (re-read, re-decide; if the mint landed, next pass sees Enew
    with local 0 and mints AGAIN — ruled correct, never republish-by-
    discovery). Other rc → P294-READOPT-MINT-FAIL, fail closed, no
    publication. rc==0 → idempotent track_held, P294-READOPT-MINT
    (Eold/Enew/gen), gres filled from NEW image with reaffirm=0.
- Subsumes (held-hi) arm: defensive mismatch guard only (-ESTALE). AG
  locks are EX-only so this arm can't fire attested; guard keeps the
  invariant airtight.
- Adopt-window exemption preserves the sess52 ruling (mount authority-
  manifest adoption inherits WITHOUT restamp; caw_adopt_retained only
  runs inside ctx->mount_adopt_window).
- v5_mount.c/h: mxfs_v5_dlm_ag_lock/_nb take local_epoch, call attested
  entry; sole callers are __mxfs_ag_dlm_lock's 3 sites passing
  READ_ONCE(pag->pag_mxfs_grant_epoch).
- STILL_HELD re-arm comment (xfs_mxfs_dlm.c ~42449) corrected: pre-290
  it falsely claimed the reaffirm minted; now the re-arm actually does
  mint through this path.

## Why post-drain provenance holds by construction
Every release-commit that zeroes pag_mxfs_grant_epoch runs strictly
after the Invariant-1 drain pipeline, so an own-bit orphan with attested
local epoch 0 cannot cover undrained pre-surrender dirt. This is the
ruling's "path that can prove post-drain equivalence" requirement —
noted in the code comment at the mint site.

## Not done yet
- 1b: rx readopt READOPT_PENDING (xfs_mxfs_dlm.c:41799 still sets
  cached=true with epoch 0 — GAP B open), P243 extension to
  cached-reclaim/rx entry paths.
- Deploy + rig verify (board baseline, STILL_HELD fault-inject
  asserting P294 fires with Enew>Eold, no Eold republish).
- Leg 8 sweep; D-488 ledger rewrite.
