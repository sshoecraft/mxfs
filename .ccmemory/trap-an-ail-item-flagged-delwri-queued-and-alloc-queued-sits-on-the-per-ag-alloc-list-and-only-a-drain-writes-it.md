---
name: trap-an-ail-item-flagged-delwri-queued-and-alloc-queued-sits-on-the-per-ag-alloc-list-and-only-a-drain-writes-it
description: TRAP (0.90.16): P128 AIL-stuck BUF with bflags DELWRI_Q|MXFS_ALLOC_QUEUED, pin=0, dwskip_n=1/why=2 = fresh inode-cluster buffer on the per-AG alloc l…
metadata:
  type: feedback
---

# An AIL-stuck buffer with DELWRI_Q|MXFS_ALLOC_QUEUED is on the per-AG alloc list

**Decoding a P128-AILSTUCK dump (xfs/xfs_trans_ail.c, 0.90.16 prints the diag
line and xfsaild's stack too):**

- `bflags=0x500020` on this fork = `_XBF_DELWRI_Q` (bit 22) | `_XBF_MXFS_ALLOC_QUEUED`
  (bit 20 — NOT `_XBF_PAGES`, which the 6.19-based fork no longer has) | `XBF_DONE`.
- `ops=xfs_inode len=32` (16 KiB): an inode-cluster buffer; two of them 32
  sectors apart = one inode chunk, logged by `xfs_ialloc_inode_init`, which
  diverts fresh cluster buffers onto `pag_mxfs_alloc_buflist` (not xfsaild's
  list) so the AG release drain publishes them before the on-disk unlock.
- `pin=0 sema=1 lock_ip=0 hold=2 onlist=1`: unpinned, unlocked, still queued.
- `dwskip_n=1 dwskip_why=2 dwsub_ms=0`: exactly ONE submit attempt, skipped
  because pinned at that moment, never submitted since.  `why=2` can only come
  from `xfs_buf_delwri_submit_nowait`, whose non-AIL caller is the lazy unlock's
  `mxfs_dlm_ag_drain_alloc_buflist_nowait`; it splices pinned leftovers back
  "for the AG's next unlock cycle".
- xfsaild idle in schedule_timeout (state S): it is not stuck; its push reports
  such an item FLUSHING (already queued elsewhere) and it cannot write it.

**So:** the item is written only by an alloc-list drain — the next
transaction-level unlock of that AG, a BAST release, or put_super's
force-release — and an AG this node keeps holding but stops using has none of
those until unmount.  Consequences measured at 4/tcp: the log tail pinned for
nine minutes, and put_super's whole-AIL wait (before the force-release drain)
never ending.  0.90.16: put_super drains every alloc list before that wait
(`mxfs_dlm_ag_drain_all_alloc_buflists`) and the nowait drain kicks a bounded
retry (`m_mxfs_alloclist_retry`) after an async log force.

Do not read `xfs_ail_push_ag_sync`'s skip of both-flag buffers as "handled":
that skip exists for the BAST path, where the drain follows; a whole-AIL wait
has no such follower.
