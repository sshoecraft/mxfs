---
name: sess1-ROOT-FIX-grant-epoch-visibility-order
description: sess1(a16ec5f2) dirent-loss ROOT PROVEN+FIXED: process_remote_grant signaled waiter BEFORE storing dir_epoch in local mirror → first modify after EX…
metadata:
  type: project
---

# sess1 — 8/tcp residual dirent-loss ROOT: grant-epoch visibility ordering (FIXED)

## Evidence chain (run5, build D0E47841, r23 loss of node4_f1.md5)
- test4 placed node4_f1.md5 at (daddr=4186520, aoff=1936) [P13-LADD 879.939].
- 0.6s later test6, 2ms after its PR→EX upgrade grant, added node6_f2 at THE SAME aoff=1936 from a near-empty stale base:
  - `P13-STALEREAD ... bf0len=2136 REUSED data block read near-EMPTY`
  - `P13-COLLIDE our=[node6_f2] disk=[node4_f1.md5] (stale-base free-slot double-alloc)`
  - `P49-STALEBASE adding=[node6_f2] firstmiss=[node4_f1.md5] — whole-block writeback will clobber`
  - `P2-EPOCHPLACE master_ep=0 valid_ep=93 b_ep=93 unestablished=1` ← THE KEY: the epoch query returned 0.
  - 25ms later `P2-LEAF-EPOCHSTALE b_ep=93 master_ep=103 — invalidate+reread` (too late).
- Root: `mxfs_dlm_process_remote_grant` (dlm.c ~3303) called `pending_signal_resource` (wakes acquirer) BEFORE reconciling the local mirror entry that stores `dir_epoch`. Woken creator's first addname ran with mxfs_v5_dlm_inode_dir_epoch()==0 → the sess2 epoch gate (xfs_dir2_data.c ~2107 requires master_ep!=0) and all tenure guards inert → stale-base RMW.
- Local-master promotions (dlm.c ~1758) already stored wk->dir_epoch before signaling — only the remote-grant path was inverted.

## Fix (build 4FC99EB9)
Reorder in process_remote_grant: (1) under table_rwlock update-in-place existing mirror (mode/gen/handoff/dir_epoch-advance) OR insert first-grant mirror provisionally; (2) THEN pending_signal_resource; (3) if inserted && !matched (unsolicited re-affirm) remove the provisional entry by (resource,owner,gen) and send the reject-release as before. ENOMEM + unsolicited semantics preserved exactly.

## Build lineage this session
C10470A6 (FACE-2 reload retry, 4/tcp 6/6) → 4EB7B98B (AG-trylock exact/near_bno) → 890B1C41 (P36 ag/comm, P67 ungate, P1-AGWAIT/AGCONFLICT) → 802D6565 (drain_evict → mxfs_drain_ilock_read forensics) → D0E47841 (**FACE-1 leak fix**: TORN-DISK-SKIP bail now kfree+up_write) → B1B84296 (P-DBLALLOC gate fix: mxfs_diag_owner) → **4FC99EB9 (grant-epoch order fix)** ← current, in test (bw6t3tnlq).

## Status vs criteria (1/2/4/8 tcp 100%)
- 4/tcp drc 6/6 on C10470A6; needs re-verify on current build.
- 8/tcp: run5 (leak fix) = full 24 rounds, single-dirent loss r23 (the bug fixed above). Pace ~395s test wall < 480s budget (run_coord tt=60*N) ✓.
- Remaining watch: AG -110 starvation (run2 only, not seen since AG-trylock), imap/create EIO double-alloc face (P-DBLALLOC detector now live for data allocs).
- Full ./run.sh suites at 1/2/4/8 still to run after drc stabilizes. Marker NOT written.
