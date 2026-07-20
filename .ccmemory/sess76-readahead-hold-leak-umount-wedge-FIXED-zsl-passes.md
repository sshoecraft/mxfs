---
name: sess76-readahead-hold-leak-umount-wedge-FIXED-zsl-passes
description: sess76: zero_silent_loss now PASSES (3/3, fs_silent=0). Fixed orphaned-readahead HOLD leak in _xfs_buf_read (build EAE5F4C0). 3 criteria still fail.
metadata:
  type: project
---

## sess76 (run 14d31183) — zero_silent_loss FIXED → PASS

### Result
`zero_silent_loss --iters 3 --dpn 100 --mode 1` = **PASS** (build `EAE5F4C076DD06896DCAAD8`):
`total_fs_silent=0 iters_with_loss=0/3 completed=3/3`. No umount wedge, no silent loss. P-DRAINSTUCK=0 on all nodes while P-RAFIX still fires (steal handled cleanly).

### Root cause (RULE 4 proven): orphaned readahead HOLD leak
The sess75 fix settled the readahead COUNT in `_xfs_buf_read` but the umount wedge merely MOVED from `xfs_buftarg_wait` (readahead-count spin) to `xfs_buftarg_drain` (LRU spin on a buffer with `b_hold>1` that never drops). Intermittent: different node each run, sometimes none.

Instrumentation:
- `P-DRAINSTUCK` probe in `xfs_buftarg_drain_rele` (b_hold>1 skip branch): stuck buffer = `daddr=... ops=xfs_bmbt hold=2 flags=0x20(XBF_DONE only) pin=0 li_empty=1` — a clean completed bmbt read pinned at hold=2 (one leaked ref).
- `P-RAFIX` stack (comm=touch): `_xfs_buf_read <- xfs_buf_read_map <- xfs_trans_read_buf_map <- xfs_btree_read_buf_block(calls mxfs_dir_bmbt_invalidate_stale) <- xfs_btree_lookup_get_block <- xfs_btree_visit_blocks <- xfs_iread_extents`. State at steal: `flags=0x15 (READ|READ_AHEAD|ASYNC), async=1, hold=3`.

Mechanism: `xfs_iread_extents` walks the dir's bmbt; `xfs_btree_readahead` prefetches left/right sibling leaves via `xfs_buf_readahead_map` (which does get_map +1 HOLD, `percpu_counter_inc(bt_readahead_count)`, sets READ|ASYNC|READ_AHEAD, submit). The same thread then SYNC-reads the same sibling via `xfs_trans_read_buf` → `_xfs_buf_read`, finding the buffer with READ_AHEAD still set and unlocked (so the async completion never ran — it would have cleared the flag + relse'd). `_xfs_buf_read` clears the flag + resubmits SYNC; the sync completion path does NOT relse, so the readahead's HOLD (and pre-fix its COUNT) is orphaned.

### FIX (build EAE5F4C0, `_xfs_buf_read` in pal/linux/xfs_buf.c ~672)
When entering `_xfs_buf_read` with `XBF_READ_AHEAD` set: `percpu_counter_dec(bt_readahead_count)` (sess75) AND drop the orphaned hold:
```c
spin_lock(&bp->b_lock);
if (bp->b_hold > 1) { bp->b_hold--; }   // guard: never free read_map's own ref
spin_unlock(&bp->b_lock);
```
Safety: READ_AHEAD-set + we-hold-the-lock ⟹ no pending async ioend (it would still own the lock) ⟹ the readahead's hold is genuinely outstanding ⟹ safe to drop. `b_hold>1` guard ensures read_map's reference survives. Marker `P-RAFIX-BUFREAD` (rate-limited) + `P-DRAINSTUCK` tripwire both KEPT (cheap, event-scoped).

### State / criteria (verify_ship.sh --status)
PASS=16 now (zsl flipped). Still FAIL (last run 2026-06-13, pre-fix — RE-RUN to confirm current):
- `fence_during_write` lost=400
- `posix_semantics_multi16` elapsed>600s
- `rsync_paired` ratio=148% (threshold ≤120%)

### NEXT
1. Strip P-DRAINSTUCK/P-RAFIX diagnostics later (optional; cheap). Fix is KEEP.
2. Chase the 3 remaining: fence_during_write (data loss on fence — correctness), posix_semantics_multi16 (>600s hang/slow), rsync_paired (perf 148%). Re-run each fresh first — today's readahead fixes may have shifted them.
3. Final gate: `verify_ship.sh` end-to-end, all PASS in one run.

Related: [[sess75-readahead-count-leak-unmount-wedge-fix]]
