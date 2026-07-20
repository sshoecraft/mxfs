---
name: sess3-ccloop-CASCADE-root-reused-inode-iget-ENOENT-create-dirty-cancel
description: sess3(ccloop) PROVEN: 2/tcp fault-test cascade = xfs_create ENOENT on a freshly-dialloc'd disk-FREE inode (reused-inode iget race) after dir_reuse ch…
metadata:
  type: project
---

## sess3 (ccloop) — CASCADE root PROVEN by instrumentation (RULE 4). Criterion NOT met.

### The 3 fault tests (fence_during_write, fault_netpartition, tcp_dlm_scaling) FAIL 1/2 in the full 2/tcp suite ONLY as a CASCADE after dir_reuse_coherency runs first (each PASSES standalone). Reproduce cheaply: `MXFS_EXTRA_MODARGS='dir_force_block=0' ./run.sh 2 tcp dir_reuse_coherency fence_during_write` → dir_reuse PASS, fence FAIL.

### A/B CONFIRMED: NOT caused by my keep_middle_block fix — repro with `dir_keep_middle_block=0` ALSO fails. Pre-existing; regressed since sess58 (which had 2/tcp 17/17).

### PROVEN ROOT (probe build 94342F7, P-CR3-CANCEL + P-CREATE-ERR1 + P-CR62 in xfs_create out_trans_cancel @ xfs_inode.c:2107):
```
P-CREATE-ERR1 dialloc/icreate err=-2 dp_ino=2099072
P-CR62 new_ino=2099099 agno=1 err=-2 disk_di_mode=00 disk_di_gen=... incore=MISS verdict=DISK-FREE=>incore-struct-stale
P-CR3-CANCEL error=-2 dp_ino=2099072 dialloc_ino=2099099 new_ino=0 trans_dirty=1 comm=bash
→ XFS Corruption of in-memory data (0x8) at xfs_trans_cancel:1061. Shutting down.
```
- xfs_dialloc hands out inode 2099099 (dirties the trans), then `xfs_icreate(tp, ino, args, &du.ip)` (xfs_inode.c:1662) → `xfs_iget(XFS_IGET_CREATE)` returns **ENOENT (-2)** for an inode that is **FREE on disk** (di_mode=0). du.ip stays NULL. Because the trans is already DIRTY, out_trans_cancel → fatal SHUTDOWN_CORRUPT_INCORE.
- The inode was just freed by dir_reuse's create+rm-rf churn and immediately reallocated → a reused-inode iget race. The repeated `DLM inode lock failed ino=131 rc=-35` (60s timeouts) is a SEPARATE hot-dir EX-handoff livelock on test2 (test1=master shows normal P64-MASTER-HANDOFF/P51-SENDGRANT); both are post-churn DLM-contention symptoms.

### RULED OUT as the ENOENT site (read): xfs_iget_check_free_state (returns 0 for IGET_CREATE free inode), XFS_INACTIVATING→out_skip (returns -EAGAIN/retry, not ENOENT), cache-hit P-IGET-ENOENT@xfs_icache.c:772 (non-CREATE path). The ENOENT comes from the cache-MISS new-inode coordination (sess127 "durable-before-visible PR+reload at iget cache-miss free-state", build 1C7F8320) OR another mxfs hook in the IGET_CREATE path. NEXT: add a probe at EACH -ENOENT return reachable from xfs_iget(CREATE) (+ dump_stack) to pin the exact site, then fix so a reused free inode either retries (EAGAIN) or creates cleanly instead of fatally ENOENT-ing a dirty create trans.

### CANDIDATE FIXES (next session):
1. Make the failing iget(CREATE) path return -EAGAIN (retry) instead of -ENOENT for a disk-FREE reused inode under DLM contention (the inode IS free; create should proceed once coordination settles).
2. OR pre-acquire/coordinate the new inode's DLM BEFORE xfs_dialloc dirties the trans, so the create can't fail fatally after dirtying.
3. Investigate the parallel hot-dir EX handoff livelock (ino 131, test2 60s rc=-35 timeouts) — may share the post-churn DLM-degradation root.

### Probes left in tree (build 94342F7, harmless log-only, error-path-gated): P-CR3-CANCEL (xfs_inode.c out_trans_cancel). dir_reuse 4/8 still PASS (probe doesn't affect it; keep_middle intact).
See [[sess3-ccloop-FINAL-status-table-all-columns]] [[sess3-ccloop-BREAKTHROUGH-keep-middle-block-fix-dir_reuse-4tcp-PASS]] [[sess127-root-fix-durable-before-visible-new-inode-iget-coord]] [[sess58-CRITERION-MET-2tcp-17of17-8consecutive]]
