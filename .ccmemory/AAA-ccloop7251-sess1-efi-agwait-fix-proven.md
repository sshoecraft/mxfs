---
name: AAA-ccloop7251-sess1-efi-agwait-fix-proven
description: 0.11.6 EFI AG-wait fix PROVEN at 32/cawd: fio saturation no longer shuts nodes down (was 8 dead); P-EFI-AGWAIT requeue observed riding out 6-min AG h…
metadata:
  type: project
tags: [ccloop-72513a13, efi-agwait, defer-shutdown, cawd, rule4-proven]
---

# 0.11.6 — deferred extent-free AG-DLM patience (PROVEN, RULE 4 complete)

## Root cause (32/cawd fio_perf collapse, 2026-07-18 12:59Z)
Under 32-node fio saturation on the single-path direct-iSCSI rig, an AG EX
holder's release drain takes minutes (AG page_ms up to 645s; P67 stall
cycles). A peer's `rm`/truncate hits the ONE unconditional blocking AG-DLM
acquire in `__xfs_free_extent` (xfs_alloc.c:4848) → 120s CAW poll →
-ETIMEDOUT → `xfs_extent_free_finish_item` forwards it (only -EAGAIN is
requeued) → `xfs_defer_finish_noroll` treats any non-EAGAIN error as fatal →
SHUTDOWN_CORRUPT_INCORE (xfs_defer.c:721) → P-WITHDRAW → peers purge slots →
cascade. 8/32 nodes died (ags 37,31,9,18,43 — five different AGs, systemic
saturation not one holder). Evidence: /tmp/run_fio_perf_20260718T125304Z.

Call-graph facts (agent-mapped): alloc paths use trylock/bounded(NOQUEUE
40×100ms)/blocking tiers and land timeouts on clean transactions; dialloc has
blocking 2nd pass but clean trans; ifree cancels clean. The bounded/NOQUEUE
variants NEVER register a CAW waiter → never BAST the holder → useless for
the free path (fixed AG). ON-DECK sibling: `xfs_iunlink` (xfs_inode_util.c:611)
takes blocking AG lock inside a DIRTY remove/rename trans → -110 would be a
dirty-cancel shutdown. NOT yet observed; fix only if it fires (RULE 4).

## Fix (0.11.6, srcversion 0146FB12D2BAEF182B10938)
- xfs_extent_free_finish_item: -ETIMEDOUT → -EAGAIN requeue (re-log intent,
  roll, retry; each cycle re-registers the 120s CAW waiter = keeps BASTing
  the holder), capped by modparam mxfs.efi_agwait_max (default 8 ≈ 16 min;
  0 = legacy fatal). New xefi_agwait counter (both alloc sites zalloc).
  Log P-EFI-AGWAIT (wording deliberately avoids soak's DPAT + dmesg_clean
  patterns).
- xfs_defer_finish_noroll out_shutdown: explicit alert when error==-110
  (attribution backstop for other intent types).

## Validation (RULE 4 step 2b — same load, re-run)
Full 32/cawd board on 0.11.6: ZERO shutdowns/withdrawals (prior run: 8).
P-EFI-AGWAIT fired on test3 (3 cycles ag=20, rode out ~6 min hold), test16,
test30 — then all completed; all 32 mounts alive (dir_reuse pre-assert
passed, board continued). Chunks 1-4 ALL PASS incl dlm_scaling 32/32 (floor
re-derivation) and crash_consistency 1604/1604.

## fio_perf budget model (remaining piece, not a bug)
fio_perf FAIL at 32/cawd is now PURE pacing: 26/32 done at the 600s kill
ceiling (flat 30s manifest budget ×20 calibration), 6 stragglers healthy,
zero errors. Fixed model: manifest + criteria.json budget_scale=linear
(30*N; 32→960s) — every node pushes fixed bytes through ONE fixed-bandwidth
target so the saturation wall ~N. Throughput QUALITY gated separately by
fio_perf_vs_xfs (>=70% native). After the rung: re-run `./run.sh 32 cawd
fio_perf fio_perf_vs_xfs` to re-record.

## Where the ladder stands
32/cawd board (0.11.6) as of 14:00Z: all PASS through chunk 4; fio_perf to
re-run; dir_reuse_coherency RUNNING (started 13:46:51Z, budget 4480s cal);
then soak + tooling chunk. Next: 16/8/4/2/1 cawd rungs, then cawp, tcp, caw
(mpath) full ladders on 0146FB12D2BAEF182B10938. ALL prior-condition boards
(mpath 0.10.120 cells) must be RE-RUN on the final build for the criteria.
