---
name: sess11run-FIX3-create-dir-before-ag-ordering-D0151E9A
description: sess11 FIX3 (D0151E9A, KEEP): fence double-shutdown root = create AG→dir vs rm dir→AG cross-node ABBA (both dirty, 60-retry rc=-110 → defer_finish sh…
metadata:
  type: project
---

# sess11 FIX3 — the fence/defer_finish shutdown ABBA (uniform dir→AG ordering)

## Proven cycle (suite-3 artifact /tmp/run_fence_during_write_20260703T230150Z)
- t2 `rm`: holds dir ino=166 EX (Approach-A defers its BAST to trans_free), needs **AG-0 EX** inside xfs_defer_finish (extent/inode free). P36-RETRY burns 59→1 (60×1s), then `DLM AG lock failed: ag=0 rc=-110` → "Corruption of in-memory data (0x8) at xfs_defer_finish_noroll (xfs_defer.c:721)" → shutdown. t3 identically 68s later. Dead FSes then failed fault_netpartition ("still writable" got=0) + tcp_dlm_scaling (0 rounds) — one root, 3 test FAILs.
- Peer create side: holds AG-0 EX **until trans commit** (t_mxfs_ag_unlocks) and waits for ino-166 EX (P-CONVBLK-DENY EDEADLK upgrade denials + P7B BAST floods at t2). Both transes DIRTY → sess5's P5D clean-trans breaker can't fire, deferred BAST honor can't run → unbreakable 60s cycle.
- Root order asymmetry in xfs_create (xfs_inode.c ~1465, v0.3.148): first dp lock was taken only AFTER xfs_dialloc → create = AG→dir; rm/unlink = dir→AG.
- Onset amplifier: 3 nodes wanting 166-EX from held-PR (fence hot-dir churn) → mass EDEADLK; faster SF handoffs (FIX2) raise collision frequency (fence shutdowns were new-severity vs the historical 2-5-name leak face).

## Fix (xfs_inode.c xfs_create, build D0151E9A, KEEP)
Take `xfs_ilock(dp, EXCL|PARENT)` + `mxfs_inode_pin(dp)` + `xfs_iunlock` BEFORE xfs_dialloc: the dir DLM EX is acquired first and its GRANT stays pinned (BASTs defer on i_dlm_pin_count) across the alloc, while the RWSEM drop of v0.3.148 is preserved verbatim (peer xfsaild iop_push trylocks the rwsem — sess33 AIL mirror-wedge cannot return). Unpin at the re-lock (success) or gated on `!unlock_dp_on_error` in the error branch (that flag exactly tracks "re-lock ran"; avoids double-unpin for icreate-stage failures). Every dirtying path now orders dir→AG → cycle impossible by construction; a dir waiter just waits out a bounded create tenure.

## Verified (fresh-cycle, D0151E9A)
fence_during_write ×3 PASS, tcp_dlm_scaling PASS 20.4s (no serialization penalty vs FIX2's 19.6s), dlm_scaling PASS, zero shutdowns.

## Known not-yet-covered siblings (replicate if suites demand)
- xfs_symlink has its own dialloc (same AG→dir shape possible under symlink-heavy load; no suite test hits it hard).
- xfs_rename whiteout dialloc.
- Dead-incarnation GRANTED entries after lazy-umount teardown (see FIX2 memory) — separate, unfixed.
- CAW transport: pin-across-dialloc means a CAW AG poll (up to 120s) keeps dir BASTs deferred that long — latency (not deadlock) concern; revalidate when CAW ladder runs.

## Gotcha that cost 20 min
After a defer_finish shutdown the node's mxfs WON'T rmmod (unmount wedges) → next run.sh prep NODE_PREP_FAIL "won't rmmod (wedged?)" → runs silently never execute (grep PASS|FAIL shows nothing). ALWAYS virsh-recycle all nodes after any shutdown before trusting subsequent runs.

Ladder state: 4/tcp full ×3 needed on D0151E9A (suite r2 17/17 was pre-FIX3 build 2BB9A4D3; r1=15/17 pre-FIX2; r3=14/17 pre-FIX3). Then 8/2/1.
