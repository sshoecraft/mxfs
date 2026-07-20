---
name: sess16run-FINAL-fix-recipe-stamp-epoch-on-dirblock-create-and-read
description: sess16(ccloop) FINAL fix recipe for dir_reuse 8/tcp: the prior-tenure evict override is RIGHT but b_mxfs_dir_epoch is too sparse — block0 stamped epo…
metadata:
  type: project
---

## sess16 (ccloop) — the precise, complete fix recipe (implement next)

The acquire-side PRIOR-TENURE evict override (mxfs_dir_evict_data_blocks, param dir_evict_prior_tenure, build EA41172C) is the RIGHT mechanism but fires <1% (10-20 vs 6000) because b_mxfs_dir_epoch is too SPARSE.

### Exact density bug
b_mxfs_dir_epoch is stamped ONLY on a genuine fresh disk read (dir_stamp_fresh = inc_rc -ENOENT). block0 (daddr=120) is read fresh ONCE early — when i_dlm_dir_valid_epoch was still 0 (before any handoff) → stamped 0 — then served as a CACHE HIT forever, never re-stamped. valid_epoch later climbs (handoffs), but block0.epoch stays 0. My override's `epoch != 0` safety guard (added to avoid resurrecting freshly-CREATED blocks, which are also epoch 0 + their own un-drained work) then SKIPS block0 → the hot stale base is never caught.

### The fix (makes the epoch dense + unambiguous, then the override covers everything)
1. **Stamp b_mxfs_dir_epoch = dp->i_dlm_dir_valid_epoch at dir-block CREATE/INIT**, not just disk read. Sites: xfs_dir2 data/leaf/free/block init (xfs_dir3_data_init, xfs_dir3_leaf_init/xfs_dir2_leaf_init, xfs_dir3_free_init, xfs_dir2_block init) — wherever a fresh dir block buffer is stamped with its magic. A block CREATED in tenure N carries epoch N (not 0).
2. **Stamp on every coherent cache-hit pass-through** in xfs_da_read_buf: when the PRE-read staleness check passes (buffer NOT invalidated, i.e. coherent for this tenure), set b_mxfs_dir_epoch = valid_epoch. (Re-stamps block0 to current each tenure it's validated, so a later handoff makes it lag.)
3. **Then DROP the `epoch != 0` guard** in the prior-tenure override: with (1)+(2), a CURRENT-tenure block (created or validated this tenure) carries epoch == valid_epoch; only a genuinely stale prior-tenure block lags. So `valid_epoch != 0 && b_mxfs_dir_epoch < valid_epoch` (incl 0 < N for a truly-never-touched-since-tenure-0 block) safely means stale. Resurrection protection now comes purely from dirty/pinned/delwri/!DONE (genuine in-flight) — epoch handles the in_ail-undestaged false-positive.
4. Ensure i_dlm_dir_valid_epoch advances RELIABLY on every cross-node handoff (it does via P65-EPOCH-ADOPT when dir_epoch_adopt=1, observed advancing 765→792). Verify it's set BEFORE the modify-evict runs on re-acquire.

### Validate
mht=50 dirwr=0, expect P-DIRWR daddr=120 count MONOTONIC (no 126→77), dir_reuse 8/tcp PASS across ~5+ clean-reboot runs (flaky race — one pass ≠ fixed). Then mht=50 tcp_dlm ≤60s, full 8/tcp 17/17, then 1/2/4. Canaries: unlink_visibility/rename_visibility/crash_consistency must stay PASS (resurrection guard); watch RULE-0 timing (extra re-reads).

### Build EA41172C = SAFE BASELINE (all params default OFF: dir_evict_prior_tenure=0, dir_nxshrink_fence=0, dir_postread_reread=0; P16 leaf-refresh removed; b_mxfs_dir_epoch field+sparse-stamps inert; MX-DOUBLEGRANT auditor KEEP/logging). Default == 48C6A95E. The prior-tenure override + b_mxfs_dir_epoch plumbing are IN the tree, gated — next session adds stamp-sites (1)+(2), drops the epoch!=0 guard (3), enables dir_evict_prior_tenure. Criterion NOT met. See [[sess16run-epoch-stamp-too-sparse-cachehit-blocks-unstamped]] [[sess16run-DECISIVE-double-grant-RULED-OUT-bug-is-buffer-layer]].</body>
