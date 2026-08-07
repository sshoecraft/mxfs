---
name: ccloop-c7ee71c6-sess103-first-dirty-capture-LANDED-0.11.436
description: sess103: step 5.3 P0/P1 LANDED (0.11.436, builds clean, NOT deployed) — authority capture moved from CIL format time to the first-protected-dirty sea…
metadata:
  type: reference
tags: [mxfs, foreign-replay, authority, step5.3, landed]
---

# sess103 — P0/P1 of the sess102 ruling is WRITTEN (0.11.436)

Builds clean. **NOT deployed, NOT measured.** srcversion `17AC8BF7EEB583CC1A36405`.
Ruling: `ccloop-c7ee71c6-sess102-GPT-ruling-capture-at-first-dirty-NOT-format`.
Inventory it came from: `ccloop-c7ee71c6-sess102-first-dirty-capture-edit-inventory`.

## What changed

The authority token is no longer resolved in `xfs_buf_item_format_segment`.
It is captured at the first protected dirtying and the formatter only
serializes it — closing the P0 unsoundness (a format-time lookup can only
report the grant installed when the CIL ran, not the grant that authorized
the mutation) and the long-owed "RULING ITEM (b)" comment.

Five files:

1. **xfs/xfs_trans.h** — `uint64_t t_mxfs_capseq` on `struct xfs_trans`.
   The capture-window key. NOT the `tp` pointer: transactions come from a
   slab and an address is reused, so a stale key could alias a fresh
   transaction and suppress the recapture — the exact stale-epoch stamp
   this change exists to prevent. Lazily assigned from a static atomic64 on
   first capture; `kmem_cache_zalloc` in both `xfs_trans_alloc` and
   `xfs_trans_dup` (VERIFIED, xfs/xfs_trans.c:124 and :292) zeroes it, so a
   ROLLED transaction correctly opens a new window.

2. **xfs/xfs_buf_item.h** — `struct mxfs_bli_auth` + the
   `bli_mxfs_auth` field on `struct xfs_buf_log_item` + the
   `mxfs_bli_auth_capture()` declaration.

3. **xfs/xfs_trans_buf.c** — one call to `mxfs_bli_auth_capture(tp, bp)` at
   the tail of `xfs_trans_dirty_buf`.

4. **pal/linux/xfs_buf_item.c** — the ladder moved into
   `mxfs_auth_classify()` + `mxfs_bli_auth_capture()`; the formatter block
   reduced to a serializer; `mxfs_buf_owner_authority()` extended to return
   `i_mxfs_auth_gen` and `i_dlm_mode` under the SAME `i_flags_lock` section
   as the state; `mxfs_ownauth_measure()` now also maps each outcome to its
   reserved non-proving status and is called from CAPTURE, not format.

5. **VERSION** 0.11.435 -> 0.11.436.

## Two facts that shaped the code (both verified, easy to get wrong)

- **`__bli_format` vs `bli_formats[0]`.** `xfs_trans_buf_set_type` writes
  the BLFT into `__bli_format` for EVERY buffer and `format_segment` copies
  it into each segment — so `__bli_format.blf_flags` is authoritative even
  for discontiguous buffers. `blf_blkno` is NOT: for multi-map, the per-map
  array holds the real block numbers and `__bli_format` is left zeroed. The
  classifier therefore takes flags from `__bli_format` and the AG from
  `bli_formats[0].blf_blkno` (map 0 — also the only map whose header the
  owner derivation reads). Passing one `blfp` for both would classify every
  discontiguous buffer into AG 0.
- **Nothing consumes the token.** Exhaustive grep: `mxfs_auth_st_proves`,
  `MXFS_AUTH_CLASS_INODE` and `MXFS_AUTH_CLASS_ICLUS` have ZERO callers, and
  `mxfs_report_replay_authority` is explicitly report-only. So this landing
  cannot change an apply/skip decision — it only changes what is stamped.

## New instrument — P240-AUTHCAP

Emitted from `mxfs_authcap_report()`, chained off `mxfs_tokcls_report()`.
Trigger MOVED to the capture path at `(win & 1023) == 0` (the sess102 trap:
the old `(tn & 8191)` advanced only ONE node of 32 across a whole dir-heavy
board chunk, so that 1052-image sample was one node's, not the fleet's).

    P240-AUTHCAP win= relog= mismatch= noblft= blftchg= nocap= pw_by_outcome:...

- `pw_by_outcome` is **the ruling's decisive cross-tab**: of each
  MXFS_OWNAUTH_* outcome, how many were dirtied while this node held
  mode >= PW on the derived owner. `none` with a high PW count => the
  RECORDER is broken; `none` with a low one => genuinely unauthorized
  modification, a live coherency defect worse than replay.
- `mismatch` is the ruling's "one buffer, two authorities" case — a re-log
  inside the same window that resolves differently. Never overwritten; the
  image is downgraded to `MXFS_AUTH_ST_MIXED`, which does not prove.
- `nocap` MUST be zero. Nonzero = a dirty path bypassing
  `xfs_trans_dirty_buf`, i.e. a plumbing hole.
- `noblft` measures the one unproven assumption in the design: that
  `xfs_trans_buf_set_type` always runs before the first dirty. If it is
  large, the capture point needs to move or the type needs plumbing.
- P239-OWNAUTH still prints, but its numbers now mean something DIFFERENT
  and meaningful — taken at capture, `durable`/`none` describe the tenure
  that authorized the mutation. The sess102 histogram (format-time) is not
  comparable to it.

## Next steps, in order

1. `MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` to deploy 0.11.436, then
   confirm srcversion on all 32 before believing any number.
2. Re-run the sess102 windows (3 rsync laps + the 8-criterion dir-heavy
   chunk) and read P240. **Watch the wall** — the re-log verify path now
   does a perag_get + RCU radix lookup per `xfs_trans_log_buf` within a
   window, which is hot. RULE 0: if the board wall regresses, that is a
   FAIL, and the fix is the per-mount authority-change sequence counter
   (bump on every `mxfs_inode_authority_*` mutation and every
   `pag_mxfs_grant_epoch` write; skip the re-derive when it has not moved).
3. `tests/ownauth_counters.sh` does NOT yet parse the P240 line — teach it.
4. Then P3 (resolve every NONE), P2 (producer-owned outcome enum — note the
   sess102 proof that `shared`/`noepoch` are structurally unreachable), P4
   (transaction-atomic replay gating), P5/P6.
