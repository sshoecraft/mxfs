---
name: sess111_drain_wedge_fix
description: sess111 — PROVEN: cache_coherency rc=-110 shutdown = release-side drain WEDGE in mxfs_ail_drain_inode_sync (cluster buf parked on alloc buflist post-…
metadata:
  type: project
---

## sess111 (ccloop run 4eef1f39 session 3, 2026-06-06) — release-drain wedge

### PROVEN root (RULE 4, direct dmesg evidence on clean build-87726318 run)
cache_coherency this run shut down test2 at t≈100s: `DLM inode lock unrecoverable:
ino=128 mode=3 rc=-110` at xfs_mxfs_dlm.c:3973 (= -ETIMEDOUT after 3×caw_lock attempts).
NOT the bnobt double-free. The HOLDER (test1) dmesg showed the cause:
- `SESS50-STARVE ino=128 our_mode=5 waiter_mode=3 waiters=8 h_ex=1 h_pr=0` repeating
  (test1 holds EX on ino=128; peer test2 waiting, test1 NOT releasing).
- `P109-INODE-DRAIN ino=128 iter=46080 still in_ail pin=0 ili_fields=0x0` — test1's
  bast_process release is WEDGED in mxfs_ail_drain_inode_sync (sess109 fn): ino=128's
  inode log item is in_ail, already iflushed (ili_fields=0), unpinned (pin=0), but
  `xfs_ail_push_all` can never make it leave the AIL → infinite spin → peer EX times out.

### Mechanism = the documented `_XBF_DELWRI_Q` collision (CLAUDE.md Design Tensions)
ino=128 (root dir, SHORTFORM fmt=1) has its dirents inline in the dinode → durability is
the INODE-CLUSTER buffer. bast_process release sequence (xfs_mxfs_dlm.c:1255-1329):
step2 drain_alloc_buflist(pag) → step3 dir_flush_data_blocks (no-op for shortform) →
step4 msleep(20)+log_force → step5 mxfs_ail_drain_inode_sync. The iflush that pushes
ino=128 into its cluster buffer happens at step4-5, AFTER step2's drain ran. The cluster
buffer then carries `_XBF_DELWRI_Q` but sits on pag_mxfs_alloc_buflist (mxfs-managed):
xfsaild's xfs_buf_delwri_queue returns false → never submitted → item stuck
XFS_ITEM_FLUSHING forever. (sess109 header explicitly named this "buf_locked on
pag_mxfs_alloc_buflist, only drained by AG-bast Phase2, not the inode path" but its fix
only covered the pushable case.)

### FIX (build `413C9D5D`, KEEP if proven) — xfs_mxfs_dlm.c mxfs_ail_drain_inode_sync
When stuck (iter≥8 && pin==0 && still in_ail), re-run `mxfs_dlm_ag_drain_alloc_buflist(mp,
pag)` for ip's AG ONCE: it splices pag_mxfs_alloc_buflist + xfs_buf_delwri_submit's the
parked cluster buffer → IO completion → xfs_iflush_done pulls the item from AIL → loop
exits → release completes → peer EX proceeds, no -ETIMEDOUT shutdown. Provably safe
(empty-list no-op). ALSO enhanced P109-INODE-DRAIN probe to dump cluster-buf state:
`cbuf_rc` (-EAGAIN=locked by other holder, -ENOENT=not cached, 0=got it), `cbuf_flags`
(check 0x400000=_XBF_DELWRI_Q, 0x100000=_XBF_MXFS_ALLOC_QUEUED, 0x20=XBF_DONE),
`cbuf_pin`, `redrained`. If re-drain doesn't clear it, the probe reveals the true state.

### VERIFY (run cc_run4 in progress, build 413C9D5D, clean reboot)
Success = no `rc=-110` / `DLM inode lock unrecoverable` shutdown; P109-INODE-DRAIN either
stops firing or shows redrained=1 then clears. If a P109 line shows cbuf_rc=-EAGAIN
(locked by another holder, NOT on alloc list) → re-drain won't fix it → next: find the
buffer-lock holder. Other cache_coherency failure modes (stale-inode double-free per
[[sess111_reframe_bnobt_red_herring]], ~5% durable lost-write) may still surface — this
fixes the drain-wedge/timeout mode only.
Related: [[sess109_lessons]] [[sess108_lessons]] [[sess111_reframe_bnobt_red_herring]].
</body>
