---
name: v0.2.X-v0.3.X version history
description: Detailed per-version log of MXFS v5 development from v0.2.2 (mkdir-validated) through v0.3.22 (sess16). Captures incremental fix narrative. For sess17+, see sess17/sess18/sess19 notes here and sess20-24_lessons.md.
type: project
originSessionId: 586111e5-07cc-45d0-b00f-761e04d0712c
---
# MXFS v5 Version History (v0.2.X - v0.3.22)

## v0.2.X — Initial v5 setup (post-mxfs.4)

- **v0.2.2**: per-AG delwri fix + peer_joined flush callback + 1.05ms blind delay (20/20 clean-disk 2-node mkdir).
- **v0.2.3**: barrier-bio replaces 1.05ms delay; Fix A stripped (20/20 mkdir validated).
- **v0.2.4**: `i_ino==0` early-return guards in all four DLM ilock hooks — fixes drop_caches → reclaim hook bug.
- **v0.2.5** (2026-04-25 morning): bidirectional AG-metadata coherency. Release-side defers `mxfs_v5_dlm_ag_unlock` via per-buffer `b_iodone` callback until AG-meta writeback completes; acquire-side stales clean AG-meta buffers in `pag_bcache`.
- **v0.2.6** (2026-04-25 afternoon): cross-node directory + inode-free coherency. Four fixes: readdir hook, AG DLM lock around `xfs_inactive_ifree`, inode-buffer staling, stale-cache reload trigger.
- **v0.2.7** (2026-04-25 evening): Concurrent-dd hang FIXED. Root cause: `mxfs_ag_dlm_lock` held `pag_dlm_lock` across CAW poll loop (up to 120s). New `pag_dlm_acquire_lock` serializes fresh-acquires.

## v0.3.X — Cached-AG DLM era

- **v0.3.0** (2026-04-25 night): Cached-AG DLM (OCFS2-style). `mxfs_ag_dlm_unlock` last-holder sets `pag_dlm_cached=true` instead of releasing. Peer BAST → `mxfs_dlm_ag_bast_work_fn` drains + releases.
- **v0.3.1**: Inode cluster buffer staling on fresh AG-acquire even when `b_li_list` non-empty.
- **v0.3.2**: Force inode reload on `iget_cache_hit` + multi-node + CREATE.
- **v0.3.3**: DLM acquire failure handling (CAW layer + XFS hook).
- **v0.3.4**: bast_process self-deadlock fix via `i_dlm_demoter` task tracking.
- **v0.3.5**: bast_process cross-thread deadlock fix — set `i_dlm_mode = NL` BEFORE calling unlock; reorder ilock_begin to check cached-mode fast-path BEFORE the DEMOTING wait.
- **v0.3.6** (2026-04-26): Cross-instance disklock stale-slot purge. Mount snapshots heartbeat timestamps, waits 10s, purges slots whose ts didn't advance.
- **v0.3.7** REVERTED in v0.3.8: bast_work serialization via `pag_dlm_acquire_lock` caused AG starvation.
- **v0.3.8**: Reverted v0.3.7. Net code = v0.3.6.
- **v0.3.9** (2026-04-26 evening, session 6): AG-bast demoting state machine. `pag_dlm_demoting` flag + `pag_dlm_demote_wq` wait queue.
- **v0.3.10** (2026-04-26, session 7): AG-bast pre-flush via `xfs_log_force(SYNC) + xfs_ail_push_all_sync + blkdev_issue_flush` BEFORE claiming demote slot. Closes Free-inode-not-marked-free family.
- **v0.3.11** (2026-04-26, session 8): CAW slot-table tombstone fix. `MXFS_CAW_TOMBSTONE_MAGIC=0x4D58444C`; find_slot skips tombstones; releases write tombstones.
- **v0.3.12** REVERTED: bast_process mode=NL-first for dirs (wrong placement).
- **v0.3.13** (2026-04-27, session 9): Bug A CLOSED — dir-strict fast-path state check (state==CACHED required for dirs).
- **v0.3.14** WRONG SITE (corrected in v0.3.16): Helper placed in `xfs_iget_cache_hit`'s IGET_CREATE block; rarely exercised due to drop_caches between iters.
- **v0.3.15** (2026-04-27, session 12): CAW deadlock CLOSED. TOCTOU race between `mxfs_v5_dlm_inode_lock` success and state publication. Fix: publish `i_dlm_mode` immediately after success.
- **v0.3.16** (sess12): Bug B residual CLOSED. Gate `mxfs_dlm_reload_inode` on `i_mode != 0 || i_nblocks != 0`. For fresh ip, skip disk read.
- **v0.3.17** (sess13): P14-INSTR diagnostic. AGI SKIP-on-bli-attached confirmed empirically wrong. Mode A surfaced (dir-fork stale-on-disk). Mode B surfaced (CAW slot exhaustion AG=1).
- **v0.3.18** (sess14): P15-INSTR CAW traffic logging. **Priority-2 root cause**: `xfs_alloc_vextent_finish` calls `mxfs_ag_dlm_unlock` BEFORE trans commit. Race: alloc → unlock → peer BAST → unlock_disk → peer reads stale → both nodes alloc same range.
- **v0.3.19** (sess15): alloc-path AG-DLM defer to `xfs_trans_free` (added `t_mxfs_ag_unlocks` list). 5/5-PASS turned out lucky-pass.
- **v0.3.20** (sess16, 2026-04-28): free-path also needed defer. `__xfs_free_extent` was still doing immediate unlock. Iters 1-4 clean. Iter-5 surfaces priority-3 inode-side family.
- **v0.3.21** (sess16): clear `XFS_AGSTATE_AGF_INIT`+`XFS_AGSTATE_AGI_INIT` in `mxfs_dlm_invalidate_ag_meta`. Forces pag fields refresh. bnobt corruption family CLOSED. 15-iter soak fails iter-4 with `agi_unlinked[]` staleness (H1).
- **v0.3.22** (sess16): H1 CLOSED via different mechanism — `xfs_iunlink` (INSERT) wasn't acquiring AG-DLM. Fix: wrap with `mxfs_ag_dlm_lock` + deferred unlock. 15-iter soak iters 1-6 PASS, iter-7 fails with bnobt-vs-AGF on-disk disagreement.

## Sess17-19 (2026-04-29 to 2026-05-01)

- **Sess17 DIAGNOSTIC**: Hypothesis (b) RULED OUT — 100% of bnobt/cntbt/inobt/finobt P14 verdicts are STALED, no SKIP. CAW grant divergence hypothesis: MXFS-level state diverges from CAW holders_ex bitmap.
- **Sess19 v0.3.29**: `mxfs_dlm_ag_drain_meta_buffers` filter at xfs_mxfs_dlm.c:1337. Old filter `list_empty_careful(&bp->b_li_list)` ALWAYS empty for AG-meta bufs (b_li_list only holds inode/dquot items). New filter accepts bufs whose bli is in AIL. Priority-2 bnobt sub-race CLOSED.
- **Sess19 v0.3.36 stress**: 1 of 3 runs hit 15/15 PASS (first ever). Approach A (per-trans inode-DLM defer list) is next-session design — partially scaffolded.
- **Sess19 lesson**: verify list semantics before filtering on lists. AG-meta bufs use `b_log_item` directly, not `b_li_list`.

## Common lessons

- **xfs_trans field init**: any new field MUST be initialized in BOTH `__xfs_trans_alloc` AND `xfs_trans_dup`; skipping dup deadlocks via NULL list iteration on rolled-trans path (sess15 lesson).
- **deferred-unlock symmetry**: when adding deferred-unlock for one site, audit ALL `mxfs_ag_dlm_unlock` call sites — alloc/free symmetry not always obvious (sess16 lesson, v0.3.19 missed free path).
- **Synchronous waits in bast_process are dangerous**: `xfs_buftarg_wait`, per-buf `xfs_buf_lock`, `xfs_buf_lock` on shared cluster bufs all deadlock (sess16 multiple revertions).
- **CLEAN rebuild required when changes span .c+.h together**: `make clean && make modules`. Incremental builds can produce stale `mxfs.ko` (burned hour in v0.2.6).
- **Diagnostic timing pressure regression**: each pr_warn batch perturbs the race window. Sess12 reached iter-4; sess13 (+P14) iter-3; sess14 (+P14+P15) iter-1. Strip ALL diagnostics before final benchmarking.
- **Log capture gotcha**: `truncate -s 0` on a file an open writer holds creates SPARSE NUL padding before subsequent appends; ~91% of fetched bytes were NULs (sess17). Use `screen -dmS` not `nohup` via sshpass for dmesg --follow over disconnect.
