---
name: ccloop-c7ee71c6-sess102-first-dirty-capture-edit-inventory
description: sess102: line-verified edit inventory for moving step-5.3 authority capture from format time to the first-protected-dirty seam (the P0/P1 blockers).
metadata:
  type: reference
tags: [mxfs, foreign-replay, authority, step5.3, edit-inventory]
---

# sess102 — edit inventory for P0/P1 (capture at first protected dirty)

Ruling and rationale: `ccloop-c7ee71c6-sess102-GPT-ruling-capture-at-first-dirty-NOT-format`.
Nothing below is written yet. 0.11.435 is the tree AND fleet build.

## The seam — VERIFIED

`xfs_trans_dirty_buf(tp, bp)` at **xfs/xfs_trans_buf.c:503** is the single
point every buffer passes through to become dirty in a transaction. Callers,
exhaustively:
 - xfs/xfs_trans_buf.c:561  (`xfs_trans_log_buf`)
 - xfs/xfs_trans_buf.c:852  (`xfs_trans_ordered_buf`)
 - xfs/libxfs/xfs_defer.c:412
It asserts `bp->b_transp == tp` on entry, so `tp` identity is available for
free as the capture-window key.

## Pieces already in the tree

 - `struct mxfs_buf_owner` + `mxfs_buf_derive_owner()` — pal/linux/xfs_buf_item.c:234/258.
   Header-based, validates magic-vs-b_ops-vs-BLFT and uuid+xfs_verify_ino.
   Handles dir3 data/block/free, dir3 leaf1/leafn, da3 node, attr3 leaf.
   Returns valid=false for DINO (correct — a cluster buffer has many owners).
 - `mxfs_buf_owner_authority()` — pal/linux/xfs_buf_item.c:~470. perag +
   RCU `pag_ici_root` lookup, NEVER an iget, validates i_ino and
   XFS_IRECLAIM|XFS_IRECLAIMABLE under i_flags_lock. Reuse verbatim.
 - `MXFS_OWNAUTH_*` 10-outcome enum + `mxfs_ownauth_name[]`.
 - Both are `static` in pal/linux/xfs_buf_item.c — the capture entry point
   should live in THAT file and be exported to xfs/xfs_trans_buf.c via a
   declaration in xfs/xfs_buf_item.h. Do not duplicate the derivation.

## Field facts (verified)

 - `struct xfs_buf_log_item` — xfs/xfs_buf_item.h:49. Add the proof sidecar here.
 - Authority state: `MXFS_AUTH_NONE 0 / UNPUBLISHED_EX 1 / DURABLE_EX 2 /
   RELEASING 3` — xfs/xfs_inode.h:249-252.
 - Inode fields: `i_mxfs_auth_state/kind/reaffirm` (u8),
   `i_mxfs_auth_gen` (u64, bumped on EVERY revoke and release-begin, never on
   install — this IS the `authority_seq` the ruling asked for, do not add a
   second one), `i_mxfs_auth_resource`, `i_mxfs_auth_epoch`, `i_mxfs_auth_incarn`.
   All written under i_dlm_lock by the `mxfs_inode_authority_*` helpers only.
 - Lock modes: `MXFS_LOCK_NL 0, CR 1, ?2, PR 3, PW 4, EX 5` —
   include/mxfs/mxfs_dlm.h:29-34. "authorizing" means mode >= PW.

## Proposed sidecar

    struct mxfs_bli_auth {
        const void *tp;        /* capture-window key; b_transp at capture */
        uint64_t owner_ino, resource, epoch, auth_gen;
        uint8_t  kind, state, dlm_mode, outcome, captured;
    };

Rules: capture only when `!captured || tp != bp->b_transp`. Keep the FIRST
capture immutable within a window; a later dirty in the SAME window that
derives a different resource/epoch increments a mismatch counter (that is
exactly the "one buffer, two authorities" measurement the ruling demanded —
do not silently overwrite). Formatter then ONLY serializes the sidecar for
the non-AG arm; it must stop doing its own lookup (that is the P0 blocker).

## The instrument that answers P1/P3/P5 — `P240-AUTHCAP`

The decisive cross-tab is **outcome x (dlm_mode >= PW)**, taken at capture,
under the same i_flags_lock read. Per the ruling's table:
 - DURABLE_EX + mode>=PW  -> expected
 - NONE + mode>=PW        -> the RECORDER is broken (state machine gap)
 - NONE + mode<PW         -> likely a genuinely UNAUTHORIZED modification
                             (a live coherency defect, worse than replay)
 - UNPUBLISHED_EX seen at all -> delegation or promotion-before-dirty needed
Also keep the non-durable BLFT histogram, and add the same-window
resource/epoch MISMATCH counter.

## Two traps to avoid

 1. The report modulus. P239 fires every 8192 tokens `(tn & 8191) == 0`
    (pal/linux/xfs_buf_item.c:~1009). That is far too coarse — a whole
    8-criterion dir-heavy board chunk advanced only ONE node past a boundary,
    so the 1052-image dir-heavy sample is one node, not 32. Drop to 1023 for
    P240, or better, expose the histogram through the existing per-mount
    debugfs dir (`mp->m_debugfs`, alongside `recovery_blocked` and
    `inode_authority`, wired at xfs/xfs_mxfs_dlm.c:42864) so it can be read
    on demand instead of waiting for a modulus.
 2. Counters are per-module-load. A deploy resets them. Snapshot/diff with
    `tests/ownauth_counters.sh <n> [snapshot]` rather than assuming a zero base.
