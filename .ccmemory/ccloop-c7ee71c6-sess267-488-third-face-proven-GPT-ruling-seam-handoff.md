---
name: ccloop-c7ee71c6-sess267-488-third-face-proven-GPT-ruling-seam-handoff
description: sess267: -488 3rd face PROVEN (truncate ILOCK poisons home-AG drain, zero retained grants) + RULE-5 ruling: contended-only post-roll ILOCK handoff at…
metadata:
  type: project
---

# sess267 — -488 third face proven + RULE-5 fix ruling

## Proven (live specimen test3/test25, 0.11.493, stacks + P67 probes)
- dd holds ILOCK_EXCL (xfs_setattr_size) across truncate defer chain,
  blocked in __xfs_free_extent → blocking mxfs_ag_dlm_lock on FOREIGN ag.
- Inode's committed log item = ONLY AIL item of its HOME ag (test3 ino
  4194433 ag=1; test25 ino 12583040 ag=3); iflush needs ILOCK → home-AG
  drain can never finish (P67-STALL-OWNER owner=dd; 77 aborts/537s+).
- Cross-node Coffman: test3 waits ag=3 (test25), test25 waits ag=1 (test3).
- P271=0 ⇒ sess263 fix correctly uninvolved; gap = xfs_alloc.c:4943
  "list_empty(t_mxfs_ag_unlocks) ⇒ no hold-and-wait edge" (FALSE premise).
- 120s poll valve dead: waiter-extension (holder node alive) extends forever.
- sess266's "holder=dd(dead)" was WRONG: dd alive, blocked in caw_wait_for_grant.

## RULE-5 ruling (GPT sess267, full text in transcript)
Contended-only **post-roll ILOCK handoff**; self-iflush REJECTED as mechanism;
no timeout/grant-steal valve (progress-based deadlock detection → fencing only).
- trylock under ILOCK; on fail in defer context: record wanted AG, return
  -EAGAIN (defer relogs+rolls); at post-roll clean seam (RELSAFE=SAFE):
  drain retained grants, DETACH clean joined inode items (pre-rejoin seam,
  avoids concurrent-ijoin li_trans collision e.g. xattr-set which takes
  ILOCK without IOLOCK), ihold, drop ILOCK(s), BLOCK for AG lock-neutral,
  then (deviation, GPT-consistent: ILOCK→AG rule not yet global — alloc
  face unfixed) PREGRANT-RELEASE to cached rather than holding grant
  across ILOCK relock; relock ILOCK canonical order, revalidate, rejoin,
  resume loop. Fast path unchanged.
- Conditions: tp clean assert, no retained grants at block, explicit inode
  ref across interval, revalidate after relock, error exits must relock+
  rejoin and preserve intents (shutdown = recovery boundary).

## Implementation plan (next session)
1. xfs_trans.h: t_mxfs_ag_want (perag ref) field.
2. __xfs_free_extent trylock-fail: NOTDEFER → old blocking (audit);
   in-defer (SAFE/UNSAFE/list_empty) → set want + return -EAGAIN
   (P271-AGWANT probe). Removes the false-premise block at 4943-4945.
3. Seam hook in xfs_defer_finish_noroll after RELSAFE_SAFE (lines 705/715):
   mxfs_defer_agwait(tp) helper — drain retained unlocks, walk t_items for
   XFS_LI_INODE (ili_lock_flags==0), xfs_trans_del_item + ihold + iunlock,
   blocking mxfs_ag_dlm_lock(want) then mxfs_ag_dlm_unlock (leave cached),
   relock ascending-ino, ijoin, iput, clear want.
4. CHECK FIRST: xfs_extfree_item.c:567-576 mxfs_efi_agwait_max=8 retry cap
   escalates -ETIMEDOUT→shutdown; new fast -EAGAINs must NOT count against
   it (they're not timeouts) — audit that path composes; also verify
   mxfs_ag_dlm_trylock cached-fast-path semantics (nesting/holders++).
5. Verify: 3× scaling_curve 32/caw (repro 2/3 runs, 90s budget) +
   rsync_paired; P271-AGWANT nonzero (path exercised); no P67 loop.
   Expect possible NEXT face: sess260 dio-alloc-under-ILOCK (restart
   protocol shape 1) still unimplemented.

## Fleet
0.11.493 sv 9CD98254D9947ED88AA35AC, still wedged with specimen (stacks
captured; safe to re-prep). Strands ag=1 bit2=test3, ag=3 bit21=test25.
