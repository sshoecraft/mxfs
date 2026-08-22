---
name: ccloop-c7ee71c6-sess384-GPT-ruling-agi-unlinked-reload-stale-live
description: sess384 RULE-5 ruling: do NOT reuse the -ENOENT destructive heal for an allocated nlink!=0 unlinked-list member; FUA home reads are not authoritative…
metadata:
  type: project
tags: [agi, unlinked, rule5, defect-361, coherency, dlm-release]
---

## Context

Measured 32/caw 2026-08-20 (sess384), reproduced 3x. One node's rsync rename
dies and cascades to half the fleet:

    Found unrecovered unlinked inode 0x80182 in AG 0x12.  Initiating recovery.
    P83-UNL-RELOAD agno=18 prev_agino=0x80211 next_agino=0x80182
    P217-RENAME-FAILSITE site=droplink_tgt rc=-117
    P217-RENAME-DIRTYCANCEL rc=-117 ... comm=rsync
    Corruption of in-memory data (0x8) at xfs_trans_cancel — Shutting down filesystem

Chain: rename-over-existing -> `xfs_droplink(target_ip)` -> nlink 0 ->
`xfs_iunlink` -> `xfs_iunlink_insert_inode` -> backref -ENOLINK ->
`xfs_iunlink_reload_next` -> `xfs_iget(UNTRUSTED)` -> `i_nlink != 0` ->
**-EFSCORRUPTED inside an already-DIRTY transaction** -> forced shutdown.
That single shutdown then cascaded to 15 more nodes via
`mxfs_dlm_noino_bast_work_fn` (#474A). 16 of 32 usable.

## The ruling (gpt-5.6-sol)

**1. Do NOT reuse the sibling -ENOENT destructive heal here.** That heal is
sound only because *a free inode cannot be a live unlinked-list member*, so
cutting it loses nothing. An **allocated** inode with nlink!=0 may be a peer's
real chain; discarding it orphans `0x80182` itself, everything reachable
through its `di_next_unlinked`, and possibly state a peer-journal replay will
later touch — replay-order-dependent damage, not just a leak.

**2. A FUA read of a home dinode is NOT authoritative in a journaling FS.**
The committed copy may be in an in-core buffer, in the log/AIL, or not yet in
the home block. FUA cannot flush another host's page cache, buffer cache, log
or AIL. "FUA-read the home block and adopt it" can mean "regress to an older
but perfectly valid image" unless home-location synchronization at DLM handoff
is already guaranteed.

**3. `XFS_IGET_UNTRUSTED` changes validation, not freshness.** It is not a
"fetch the freshest shared-disk copy" flag, and `xfs_iget` returns a CACHED
inode when one exists. Upstream's `ASSERT(next_ip == NULL)` for the cache is
**DEBUG-only**, so on a production build nobody has ever checked. A stale
in-core copy of a peer's inode is indistinguishable from real AGI corruption
at this site. **Log the cache hit/miss first.**

**4. "This path never returns an error into a dirty transaction" is NOT a safe
invariant.** Real I/O errors, verifier failures and genuine corruption after
the transaction is dirty still must shut down — XFS cannot commit and cannot
roll back partially modified in-core metadata. The correct, narrower goal:
*prevent expected cross-node coherency misses from being classified as
corruption after the transaction is dirty.*

**5. The strong fix lives at the DLM acquire/release boundary, not in rename.**
Release must not complete until the next owner can observe a mutually
consistent state: commit/log force, push AND WAIT for both the AGI buffer and
the dinode buffer of the newly unlinked inode, completion through the real
shared-storage path, plus cache invalidation on the acquirer. The AGI and the
dinode must represent the SAME logical transition at handoff. A peer-journal-
durable transaction is insufficient when other nodes read only home blocks.

**6. If visibility cannot be guaranteed**, preserve the chain instead of
cutting it: support an "unresolved predecessor" backref state — write our
`di_next_unlinked` to the existing head, install the new AGI head, do NOT
discard the old chain, mark the next inode's backref unresolved and rebuild it
later by walking the bucket under the AG DLM. Requires auditing every
`xfs_iunlink_remove`, reclaim, recovery and inode-reuse consumer.

## The one discriminating experiment

Release-side raw read-after-write while the previous owner STILL holds the AG
DLM. Per unlinked-list transaction record a transition cookie (AG, bucket, old
and new AGI head, agino, commit LSN / slice seq, dinode nlink +
`di_next_unlinked` + gen + changecount, DLM epoch). Before unlock: force the
log, push and WAIT for both the AGI buffer and the dinode buffer, then issue —
through a bounce buffer that bypasses the XFS buffer and inode caches — the
same read the acquirer will use, and verify both blocks jointly describe the
transition. Publish the cookie in the LVB/release trace; the next owner
raw-reads the same blocks right after acquire.

Interpretation:
- releasing node's own raw read already old -> release flush coverage/order wrong
- releaser sees new, acquirer sees old -> storage/multipath/target cache coherence
- both raw reads new but `xfs_iget` sees nonzero -> local cache invalidation wrong
- AGI new but dinode old on the releaser -> release exposes a SPLIT transition
- home blocks old but log committed -> relying on log authority with no way for
  peers to observe it

## Hazards of FUA-reading under the AG DLM in a dirty transaction

- A read consumes no log space, but the held reservation is pinned while
  waiting; at scale that is log-reservation starvation.
- Deadlock risk if satisfying freshness needs a log force / AIL push / inode
  writeback / callback that itself needs the AG DLM, the inode lock, the buffer
  lock or the blocked worker.
- Never invalidate or overwrite a buffer that is transaction-locked, dirty,
  pinned or joined elsewhere; never hand-patch a cached inode's `i_nlink` from a
  raw read (bypasses inode locking, VFS state, log-item and reclaim checks).
- Several dinodes share an inode buffer, so a raw home block can be older than
  local dirty changes to unrelated inodes in it — diagnostic use only, never
  install it into the buffer cache.

## Containment principle for the cascade (independent fix, do it FIRST)

A node may not relinquish shared-lock authority until it is known quiescent or
fenced, and **another node's local XFS shutdown is not evidence that every
peer's in-core filesystem is corrupt**. Sequence: stop originating writes ->
revoke lease -> fence -> only then treat its locks as recoverable -> recover its
slice under an exclusive recovery lock -> invalidate survivors' affected caches
-> resume grants. For `mxfs_dlm_noino_bast_work_fn`: callbacks must be
idempotent, must not assume the inode is cached, must not need a lock the
withdrawing path can never release, must mark/revoke/defer into a recovery
context with explicit ownership, and callback failure must poison that one
resource or withdraw this node — never recursively force unrelated shutdowns.

## Implementation order

1. branch probe + iget cache hit/miss  ← sess384 landed this (P84-UNL-RELOAD-LIVE / -OK)
2. release-side raw read-after-write experiment with a DLM epoch cookie
3. verify whether AG DLM release waits for BOTH the AGI and the dinode home writes
4. fix release/acquire visibility if deficient
5. bounded stale-read retry as defence in depth
6. NEVER the destructive heal for an allocated nlink!=0 member
7. chain-preserving unresolved-backref handling, or a preflight under a
   continuously held AG DLM, if visibility cannot be guaranteed
8. fix the shutdown/fencing callback cascade before more 32-node stress
