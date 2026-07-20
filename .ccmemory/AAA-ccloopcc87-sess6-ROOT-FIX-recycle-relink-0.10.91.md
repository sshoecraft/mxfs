---
name: AAA-ccloopcc87-sess6-ROOT-FIX-recycle-relink-0.10.91
description: sess6: P135 root cause CONFIRMED (P139 fired 14x, always reused ino under churn+fault_netpartition, via xfs_create CREATE path). FIX: re-link via ino…
metadata:
  type: project
tags: [ccloop-cc87fed3, pr_sweep, build-0.10.91, RULE4, ROOT-FIX]
---

## Result: hypothesis CONFIRMED with strong, repeated direct evidence (build 0.10.90, srcversion D74F78B94E1873B2C9E1648)

Re-ran the exact repro with P139-RECYCLE-UNLINKED (entry check in `xfs_iget_recycle`) + P140-RECLAIM-COMMIT
(audit trail in `xfs_reclaim_inode`) instrumentation. **P139 fired 14 times in one run** (not a rare fluke) —
every single hit: `comm=mkdir` (one `comm=stat`), same reused `ino=0x83` (131), full call trace every time:
`xfs_create -> xfs_icreate -> xfs_iget -> [cache-hit, IRECLAIMABLE, xfs_iget_recycle]`. Cross-referenced
against P140 (1004+ real reclaim commits logged, ~27 for this same ino=0x83 alone) — confirms this specific
inode number is under EXTREMELY heavy reclaim/reuse churn during `dir_reuse_coherency`+`fence_during_write`+
`fault_netpartition`, and repeatedly, `xfs_iget_recycle` finds `list_empty(&inode->i_sb_list)` true — i.e. it
is about to recycle a `struct inode` that VFS's own `evict()` has ALREADY fully unlinked from `sb->s_inodes`,
while the per-AG radix tree entry that made this struct findable at all is STILL present (removed only near
the very end of `xfs_reclaim_inode`, after the point where a concurrent lookup can already have found and
started recycling it).

This is DIRECT proof of the corruption mechanism Fable predicted (see sibling memory
`AAA-ccloopcc87-sess6-fable-consult-recycle-race-hypothesis`): recycling an already-VFS-evicted inode object,
then handing it back out as live WITHOUT re-establishing its `sb->s_inodes` linkage, is exactly what produces
a later self-referential entry once THIS (second) incarnation is itself eventually evicted — matching pr_sweep's
observed `visited=2..3` short-self-loop signature precisely.

## Fix applied (build 0.10.91, srcversion D1C2FDFC88DDE4D0B0FA3E3)
`xfs_iget_recycle` (xfs/xfs_icache.c, entry, before `xfs_reinit_inode` runs): when `list_empty(&inode->i_sb_list)`
is found true, call `inode_sb_list_add(inode)` (stock, `EXPORT_SYMBOL_GPL`, self-contained — takes
`s_inode_list_lock` itself, safe to call here since it's not held) to re-establish the linkage before
continuing — exactly what a fresh `xfs_iget_cache_miss` does for a brand-new inode via `inode_insert5`.
`list_empty()` is unambiguous (a list_head whose own next/prev point to itself is not linked into ANY list
right now), so this is a safe, targeted repair, not a guess. Kept a one-time-capped (`atomic_inc_return <= 50`)
`pr_warn` so the condition remains visible/countable without flooding across a long soak.

## Not yet fully root-caused: WHY the radix-tree-removal happens so late relative to VFS unlink
Still don't have a byte-for-byte proof of "which exact thread's xfs_reclaim_inode call raced which exact
thread's xfs_iget_cache_hit call" (would need matching ip= pointer values between a P140 and a P139, which
this run's data didn't cleanly show — the ip= addresses differ between the two logs, consistent with the
radix tree entry surviving across MULTIPLE reclaim+reuse cycles of DIFFERENT physical struct addresses for the
same ino, i.e. this may be happening repeatedly/independently rather than as one single isolable race
instance). The FIX (re-link on recycle) is correct and safe regardless of the precise blow-by-blow, since it's
restoring an invariant (a live inode must be linked) that must ALWAYS hold true — but if validation still
shows P139 firing at a similar rate on 0.10.91 (now succeeding at fixing instead of corrupting), that's
expected and fine; what must NOT happen is the P135 cycle detector or the drop_pagecache_sb hang recurring.

## Validation plan
1. Re-run the identical repro (`dir_reuse_coherency fence_during_write fault_netpartition` @ 2/caw,
   MXFS_DEV=/dev/mapper/mpatha, live dmesg -T -w both nodes) on 0.10.91.
2. Expect: P139 may still fire (that's fine, it's now a self-healing event, not left uncorrected) but
   P135-PRSWEEP-CYCLE should NOT fire, and fault_netpartition's drop_caches step should NOT softlockup.
3. If clean: this is the real fix. Proceed to re-validate 2/caw FULL suite fresh, then resume the
   1/2/4/8/16/32 sweep from where sess5/sess6 left off (1/caw already had a fresh 17/17 on an earlier build;
   worth a spot re-check given this touches core inode lifecycle code, but full priority is finishing 2/caw
   then 4/8/16/32 fresh).
4. If P135/hang STILL recurs on 0.10.91: the double-add mechanism has a second source not yet found (e.g. a
   path through xfs_iget_cache_MISS creating a genuinely SEPARATE second struct inode object for the same ino
   while the recycled one is also alive -- would need a parallel "is this ino already resident" check in the
   cache-miss path too). Re-open RULE 4, do not re-guess.

## Cluster state
test1+test2 freshly reset and on 0.10.91 (ALL_OK) as of this checkpoint, about to re-run the repro.
