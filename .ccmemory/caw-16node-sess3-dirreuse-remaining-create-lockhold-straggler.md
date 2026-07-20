---
name: caw-16node-sess3-dirreuse-remaining-create-lockhold-straggler
description: 16/caw dir_reuse (post-dedup): sole blocker = EX-grant STARVATION on shared dir ino=131 in caw_wait_for_grant (PROVEN: 4 nodes stuck in xfs_create→xf…
metadata:
  type: project
---

## 16/caw dir_reuse — remaining blocker (CORRECTED, definitive) — ccloop 26c41354 sess3, 2026-07-06

Read with [[caw-16node-sess3-dedup-fixes-wedge-new-ilock-stall]] (dedup breakthrough) + [[sess127-shared-dir-create-starvation-after-removing-harmful-stale-flag]] + [[sess50_lessons]] (prior art).

### CORRECTION of the earlier "leak" hypothesis — it is NOT a leak
Broadened live-capture (poll all 16 nodes for any task with xfs_create in stack + etimes>=15) caught it DEFINITIVELY. FOUR nodes simultaneously (test1/13/14/16, et 16-32s), IDENTICAL stack:
```
msleep → mxfs_pal_sleep_ms → caw_wait_for_grant+0x253 → mxfs_dlm_caw_lock+0xa3a →
mxfs_v5_dlm_inode_lock+0xff → mxfs_dlm_ilock_begin+0xc7f → xfs_ilock+0xa4 →
xfs_create+0x4b3 → xfs_generic_create → xfs_vn_create → lookup_open → open_last_lookups → openat
```
The create is STUCK in `caw_wait_for_grant` (dlm_caw.c) polling for the EX grant on the shared dir inode (ino=131). It is NOT leaked — it's actively waiting. The earlier test14 P132 / test11 open_last_lookups "no writer found" were DOWNSTREAM: a reader (ls/md5sum) blocks on the dir lock held by whichever node currently holds/awaits dir-EX; the actual holder rotates and is a create in caw_wait_for_grant.

### ROOT: EX-grant STARVATION on the hot shared dir inode (sess50/sess127 family)
16 nodes all need EX on ino=131 to add a dirent (create). `caw_wait_for_grant` DEFAULT (mxfs_caw_fair_handoff=0) is the self-promote FREE-FOR-ALL: every EX waiter polls + self-promotes the instant `is_compatible`; release sets `yield_to = ALL` waiters (no ordering) → an unlucky node's poll cadence systematically loses → starves to 120s → barrier/2240s-timeout FAIL. Intermittent single/few-node straggler. Existing anti-starvation is INSUFFICIENT at 16: `inode_mht_ms=300` (batch min-hold, DEFAULT ON) + sess50 `defer_for_waiter` are active but a node still starves.

### FIX TO TEST (RULE 4) — NEXT ACTION
`caw_fair_handoff=1` (dlm_caw.c, default 0): release picks ONE round-robin next EX waiter via `caw_pick_next_ex_waiter` (first bit after releaser, INODE only) → FIFO-ish fairness → bounds each waiter's wait to ~N×hold. Prior handoff memory said it was "TOO SLOW (times out)" — BUT that was measured WITH the wedge compounding (load 870, tag exhaustion). The wedge is now GONE (dedup), so re-test: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="bast_wq_max_active=16 noino_bast_dedup=1 caw_fair_handoff=1" ./run.sh 16 caw dir_reuse_coherency`. Watch: no straggler (all nodes progress), completes <2240s. Build D8BEF5A5 already has all params.
- If fair_handoff fixes starvation but too slow → cap the chosen-waiter poll cadence lower (MXFS_CAW_POLL_MAX_MS=25 → ~3ms for fair-handoff waiters so the chosen node reacts fast), OR reduce inode_mht_ms (300→ lower shortens the round-robin cycle), OR both.
- If starvation persists → the round-robin isn't fully engaging (sess2 noted "may not fully engage"); consider aging/longest-waiter-first in caw_wait_for_grant.

### Confirmed working config so far (build D8BEF5A5)
`bast_wq_max_active=16` (bound bast wq — fixes block-tag-exhaustion wedge) + `noino_bast_dedup=1` (collapse same-inode no-inode BASTs — fixes CAS-livelock wedge). Both PROVEN to remove the wedge (0 exhaustion/EIO, load ~1-2). caw_unlock_backoff probably droppable. Make the two default-on once dir_reuse fully passes; then FULL suite@16 (MXFS_SETTLE_MS for cascade mode1) + dlm_scaling (mode3) + 32 nodes.
