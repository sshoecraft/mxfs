---
name: ccloop4dd7-sess3-B-ROOT-reload-shrink-dcache-self-deadlock
description: sess3 ROOT PROVEN+FIXED v0.11.56: reload_inode's shrink_dcache_parent ran child sync-inactivation while holding the shared cluster buf locked = b54r1…
metadata:
  type: project
tags: [ccloop-4dd7, root-cause, reload-shrink-dcache, buffer-lock]
---

# ccloop-4dd7 sess3 ROOT #2 — reload-inode dcache-shrink self-deadlock (PROVEN, FIXED v0.11.56 = 7E70702E)

## The proof chain (b55r3, live)
- P-BUFLOCK-STUCK (new v0.11.55 probe) fired 20× on test1: daddr=128 (AG0 inode cluster) len=32
  ops=xfs_inode flags=0x20 hold=7 **lock_ip=0x0** ioend_seen=1 — buffer locked with NO xfs_buf_lock caller.
- evring decode (scripts/decode_bufev.py fields): SUBMIT(sync READ, pid≡2097 mod 4096) → BIO → BIOEND →
  IOWAIT. One read, by the leaker, completion fine, never released.
- Live pid scan: 84017 (rmdir) ≡2097, D-state, FULL /proc/84017/stack =
  do_rmdir → lookup_dcache → mxfs_drevalidate → xfs_dir_lookup → xfs_ilock →
  **mxfs_dlm_ilock_begin → mxfs_dlm_reload_inode → shrink_dcache_parent** → __dentry_kill →
  iput → evict → xfs_fs_destroy_inode → xfs_inode_mark_reclaimable → **SYNC xfs_inactive** →
  truncate → defer → trans_roll → __xfs_trans_commit → xfs_inode_item_precommit → xfs_imap_to_bp →
  xfs_buf_lock (SAME daddr-128 cluster the reload holds locked) — SELF-DEADLOCK.
- b54r1's "leaked ACQUIRING with no live acquirer" was THIS same shape mis-read: the earlier stack sweep
  used `head -18` and cut the reload frames below destroy_inode. The dir sits ISTATE_ACQUIRING because
  its acquirer never leaves ilock_begin; every peer BAST defers (bast_during_acq) forever → peer rmdir
  -110 after 184s → dirty-cancel shutdown. Node-side: do_rmdir dputs BEFORE inode_unlock(parent) on this
  6.8 base, so the whole node convoys behind parent i_rwsem with only-VFS wchans.

## Why sync-inactivation runs there
xfs_icache.c xfs_inode_mark_reclaimable: multinode policy = synchronous xfs_inactive (AGI-recycle-race
protection), EXCEPT journal_info!=NULL (sess41 in-trans defer→inodegc). Lookup revalidation has
journal_info==NULL → sync path taken inside the reload.

## FIX (v0.11.56)
mxfs_dlm_reload_inode: the S_ISDIR dcache-invalidation block (shrink_dcache_parent + dput +
invalidate_inode_pages2) MOVED from mid-function (cluster buf locked, i_lock held) to the function TAIL
after `up_write(&ip->i_lock); xfs_buf_relse(bp);`. Child inactivation then runs to completion (no held
buffer), bounded, and the acquire completes. S_ISREG arm (invalidate_mapping_pages, non-blocking,
cannot evict) left in place. Bail arms return before the tail (unchanged: they never shrank).

## Instruments that made it visible (keep)
- P-BUFLOCK-STUCK (pal/linux/xfs_buf.c xfs_buf_lock, down_timeout 30s loop, prints b_lock_ip+evring).
- ACQUIRING setter stamp + P-ACQ-ORPHAN-RECLAIM (xfs_mxfs_dlm.c bast_notify ACQUIRING branch;
  inflight==0+strikes>=8 → DEMOTING+queue bast_work). NOTE: in THIS root the acquirer is live, so
  inflight>=1 and the reclaim correctly does NOT fire.
- scripts/dialloc_round.sh: prep + iwr=1 + watch_ino=131 + LIVE journalctl -kf streams per node
  (journald wraps in <2min at probe volume; post-hoc capture lost two failure windows).

## Open after this: b55r2 flavor (dialloc recycle DISK-LIVE -117 dirty in xfs_create — platter REGRESSED
to an older life's LIVE image between tenure 1 free and tenure 4 realloc; suspect stale cluster-buffer
whole-write by peer / late destage; P28-IWR+FREEWR now enabled in rounds to catch it). Ladder resets at
v0.11.56.
