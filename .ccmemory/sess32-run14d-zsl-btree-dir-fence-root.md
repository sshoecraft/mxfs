---
name: sess32-run14d-zsl-btree-dir-fence-root
description: sess32(14d): zsl ROOT = all dir eviction fences bailed on BTREE-format dirs (returned true=lie). Fix FF401F22 built UNTESTED. dirwr passthrough fixed.
metadata:
  type: project
tags: [zero_silent_loss, btree-dir, coherency, ccloop-14d31183]
---

# sess32 (ccloop 14d31183) — zero_silent_loss root cause + fix (UNVERIFIED)

## Status
17/18 criteria PASS; only `zero_silent_loss` FAILs. Build `FF401F225E7B0BA351296AE` carries the fix, **built but NOT yet run** (relay boundary hit right after build).

## ROOT CAUSE (proven by elimination + probe forensics)
The dpn=100×16-node mkdir storm grows the shared dir (ino 131) past EXTENTS into **BTREE format**. From that moment ALL THREE dir coherency fences silently turned off:
- `mxfs_dir_evict_data_blocks` (xfs_mxfs_dlm.c): `if (format != EXTENTS) return true;` — **returns true = "all evicted" LIE** → callers (`mxfs_dlm_dir_modify_refresh` / `consumer_refresh`) advance `i_dlm_dir_evicted_gen` → `P106-MR-SKIP` fast-paths every modify onto the stale base.
- `mxfs_dir_drain_evict_data_blocks`: same format bail (`return 0`).
- Evidence: `DIR-STALE-SKIP ino=131 blk=45 buf_gen=0 inode_gen=365 pin=1` (block NEVER refreshed across 365 reloads while node RMW'd it) with `P-ACQ-DRAIN-EVICT`/`P-EVICT-*` = 0 in the loss window. Both zsl failure modes follow: quiet dirent loss (stale dir-block RMW drops peers' dirents) and the cluster-wide `corrupt dinode 131 (btree extents)` storm (stale bmbt vs fresh dinode: `P133-BMBT-STALE-SKIP in_ail=1 delwri=1` immediately before all 16 nodes shut down).

## THE FIX (in FF401F22)
Gate on **extents-loaded, not fork format**: `for_each_xfs_iext` works for BTREE forks once extents are in-core (always true by modify time). Both fences now: BTREE + `xfs_need_iread_extents` → return false/skipped (gen NOT advanced); else run the normal iext snapshot loop. `MXFS_DIR_DRAIN_MAX` 32→64 + per-entry `lens[]`.

## CRITICAL TRAP — first fix attempt (`70926D6B`) WEDGED the cluster
v1 enumerated dir blocks via per-AG buffer-cache owner-walk (`mxfs_dir_collect_owned_bufs`, still in tree as `__maybe_unused`). Correct but **O(whole buffer cache) per modify**; gen never advances mid-storm (own in-flight blocks undurable) → full rewalk per create → dir-EX tenures balloon → `SESS50-STARVE` ping-pong → verify hung (`completed=0/1`, find non-numeric). NEVER put a cache walk in the dir-modify hot path.

## Test-infra fixes this session
- `scripts/sess88_workload_a_modeN_baseline.sh`: `INSMOD_OPTS` now honored, **including the sess18 trap**: `prep_tcm_node.sh` insmods param-less first, so the script now rmmods before `insmod $MODULE ${INSMOD_OPTS:-}`. Verify with `cat /sys/module/mxfs/parameters/dirwr` — two runs silently ran dirwr=0 before this.
- New probe `P134-BMBT-WR/-REVERT` in xfs_buf.c xfs_buf_submit (dirwr/instr-gated): bmbt write timeline + plain-read disk compare + stack.

## NEXT (in order)
1. Clean cluster (check wedged: `rmmod` per node, virsh destroy/start failures), run `INSMOD_OPTS="dirwr=1" ./tests/criteria/zero_silent_loss.sh --iters 1` on FF401F22. Expect: P-EVICT-DONE/SKIP firing for ino 131 in btree phase, DIR-STALE-SKIP↓, loss=0, no starvation (watch SESS50-STARVE).
2. If quiet loss persists: remaining hole = destaged-AIL-residue blocking eviction (`P-EVICT-SKIP in_ail=1` on DESTAGED blocks). Planned remedy (researched, not yet applied): the eager evict's `undurable` test uses raw `in_ail` — split by `mxfs_dir_buf_is_undestaged()`; for destaged residue retire the AIL item via `xfs_buf_item_done(bp)` (xfs_buf_item.h:61; = exactly what IO completion does; bli_refcount must be 0, buffer locked, !dirty !pinned) + clear `_XBF_DELWRI_Q` (sanctioned lazy delwri removal — `xfs_buf_delwri_submit_prep` drops flag-cleared buffers without writing). Do NOT xfs_buf_stale (ghost-buffer trap, and upstream push asserts !STALE).
3. Separate open mechanism (do AFTER zsl green, may not block it): P124-ALLOC-REVERT fired all 16 nodes (xfsaild pushes prior-tenure AG0 bnobt/cntbt root over peer's durable image; `ag_held=1 ex_pop=1 buf_gen=0 pag_gen=1 in_ail=1 dirty=0`; P117/P77/P86 never fired = AG-meta read fence also bypassed silently — suspect tenure-id stamping or pag_gen frozen at 1, P102-ACQ fired exactly once/node). Same destaged-AIL-residue treatment likely applies in `mxfs_ag_meta_invalidate_stale`.
4. Then iters=3 full criterion, then `verify_ship.sh` end-to-end.

## Probe cheat-sheet for this hunt
- dmesg ring wraps under dirwr=1 — ALWAYS mine `journalctl -k --since '<UTC>' --utc`.
- Loss runs come in 2 modes: quiet (26-70 lost, no corruption) and storm (~1590, corrupt dinode 131). Same root.
