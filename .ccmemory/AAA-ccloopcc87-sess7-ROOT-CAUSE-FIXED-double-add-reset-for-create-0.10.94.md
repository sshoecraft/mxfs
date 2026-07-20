---
name: AAA-ccloopcc87-sess7-ROOT-CAUSE-FIXED-double-add-reset-for-create-0.10.94
description: sess7: P135 TRUE root cause PROVEN+FIXED (build 0.10.94, srcversion 1600324A1B12DB4574AA1C6). xfs_setup_inode unconditional inode_sb_list_add double-…
metadata:
  type: project
tags: [ccloop-cc87fed3, P135, root-cause, FIXED, build-0.10.94, RULE4, RULE5-not-needed]
---

## Bottom line
sess6 handed off a REVERTED fix (blind re-link in xfs_iget_recycle, made things worse) and a
"working theory" that xfs_iget_recycle should bail (-EAGAIN) on list_empty(&inode->i_sb_list).
That theory was WRONG (see below). sess7 found the ACTUAL root cause via a completely different,
more direct diagnostic, fixed it with a 1-line change mirroring stock kernel's own idiom, and
validated CLEAN across the exact repro that broke sess5/sess6, plus the full 16-test (non-soak)
2/caw suite. This is a real, proven, minimal fix -- not a mitigation.

## Why sess6's P139/list_empty framing was backwards (important -- don't re-chase this)
Traced the full lifecycle: `xfs_inode_mark_reclaimable()` (which sets XFS_IRECLAIMABLE) has
EXACTLY ONE caller in the whole tree: `xfs_fs_destroy_inode()` (pal/linux/xfs_super.c:773), which
is ONLY ever invoked as the `->destroy_inode` VFS callback from generic `evict()` -- and generic
evict() calls `inode_sb_list_del()` (unlinking i_sb_list) STRICTLY BEFORE `->destroy_inode` runs,
as part of the SAME evict() call. Therefore: **`list_empty(&inode->i_sb_list) == true` at
xfs_iget_recycle's entry is the universal, by-construction, ALWAYS-true state for every
IRECLAIMABLE inode** -- P139 firing is 100% expected/harmless, not an anomaly. sess6's "unlikely()"
annotation and "not a rare fluke" framing were based on a wrong premise. Confirmed live: added a
complementary P142 check (fires when an IRECLAIMABLE inode's i_sb_list is found STILL LINKED at
recycle entry -- the case that WOULD indicate a genuine problem on this path) -- **P142 fired ZERO
times** across multiple full validation runs, while the real corruption (P141, see below) fired 7x
per run. The recycle/IRECLAIMABLE path was never the culprit.

## The real mechanism (proven via direct instrumentation + live stack trace)
`xfs_setup_inode()` (pal/linux/xfs_iops.c, called from xfs_iget's post-hit/post-miss block AND
from xfs_icreate -- the ONLY two call sites, and the ONLY call site of `inode_sb_list_add()`
anywhere in the mxfs tree) called `inode_sb_list_add(inode)` **unconditionally** -- unlike stock
kernel's own `inode_insert5()` (fs/inode.c), which guards with
`if (list_empty(&inode->i_sb_list)) inode_sb_list_add(inode);`.

`list_add()` on an already-linked node splices it into a NEW position without unlinking the OLD
one first -- it only fixes up the NEW neighbors; the OLD neighbor's `->next` is left dangling,
still pointing at this inode. Later, when this inode is genuinely evicted, THAT specific stale
neighbor's dangling pointer + the inode's own now-self-referential list_head is exactly the
"visited=2..3 short cycle" signature pr_sweep's P135 detector and stock `drop_pagecache_sb` (via
`iterate_supers` -> `list_for_each_entry(inode, &sb->s_inodes, i_sb_list)`) choke on forever (no
natural termination -- confirmed multiple times this session and in sess5/6, the softlockup spins
600s+ with zero self-recovery, requires cluster_reset_n.sh).

**Culprit found by instrumenting the ONE true call site directly** (P141-SETUP-DOUBLE-ADD,
pal/linux/xfs_iops.c xfs_setup_inode, checks list_empty right before the add) instead of one step
removed at recycle entry. Fired 5-7x per repro run, 100% reproducible. Live stack trace (dump_stack
capped to first 5 hits) on the FIRST hit:
```
xfs_setup_inode+0x209/0x210 [mxfs]
xfs_icreate+0xcc/0x100 [mxfs]
xfs_create+0x5b3/0x1400 [mxfs]
xfs_generic_create+0x283/0x3e0 [mxfs]
xfs_vn_create+0x17/0x30 [mxfs]
lookup_open.isra.0 -> open_last_lookups -> path_openat -> do_filp_open -> do_sys_openat2 -> __x64_sys_openat
```
A single, clean `open(O_CREAT)` syscall (bash's `>` redirect, comm=bash matches) -- NO retry loop
visible in the trace. Since there's no double-call WITHIN this trace, the prior linkage had to be
a leftover from an EARLIER, separate create that was never unlinked.

That points at `mxfs_dlm_reset_inode_for_create()` (xfs_mxfs_dlm.c:19116) -- the "MXFS multi-node
CREATE" cache-hit branch in xfs_iget_cache_hit (xfs_icache.c ~1070, gated on
`ip->i_mount->m_mxfs_dlm && (flags&XFS_IGET_CREATE) && !(ip->i_flags&XFS_IRECLAIMABLE) &&
(mode!=0||nblocks!=0)` -- NOTE: no `!mxfs_v5_dlm_is_single_node()` guard here, unlike the sibling
sess38/sess40 blocks -- **this path is NOT excluded at 1-node, the bug can manifest at 1/caw too,
not just multi-node**). This function resets a struct's XFS-level content (mode=0, nlink=0,
forks destroyed, size/nblocks/diflags cleared) IN PLACE for reuse by a brand-new file, for a
struct that is explicitly NOT IRECLAIMABLE -- i.e. still fully VFS-linked/live, never evicted
(comment: "our local cached struct may carry stale allocated content from this node's PRIOR use of
the inode"). It resets everything EXCEPT `i_sb_list` -- confirmed by reading the full function body,
zero mention of i_sb_list/inode_sb_list_del anywhere in it. So the struct stays validly linked at
its OLD position the entire time. When the reused ino later reaches `xfs_icreate`'s
`xfs_setup_inode()` call, i_sb_list is STILL linked from the prior incarnation -> double-add.

## The fix (build 0.10.94, srcversion 1600324A1B12DB4574AA1C6)
`pal/linux/xfs_iops.c`, `xfs_setup_inode()`: changed the unconditional
`inode_sb_list_add(inode);` to mirror stock `inode_insert5`'s own guard exactly:
```c
if (likely(list_empty(&inode->i_sb_list))) {
	inode_sb_list_add(inode);
} else {
	/* P141-SETUP-SKIP-DOUBLE-ADD diagnostic, capped 200 -- confirms the guard
	 * is engaging (skipping exactly the redundant add), not a behavior change. */
}
```
Verified SAFE for every other caller before implementing (not a guess -- RULE 4 compliant):
- IRECLAIMABLE recycle path: i_sb_list is ALWAYS empty at this point (see "why P139 backwards"
  above) -- guard is a no-op there, unchanged behavior, add always proceeds.
- Cache-miss (xfs_inode_alloc) fresh structs: i_sb_list is either freshly INIT_LIST_HEAD'd by the
  slab ctor (`xfs_fs_inode_init_once` -> `inode_init_once`, fs/inode.c, runs once per slab PAGE)
  or left properly empty by a prior clean `__xfs_inode_free()` (which only ever runs AFTER a full
  evict()-driven reclaim) -- confirmed via full lifecycle trace of `xfs_reclaim_inode` ->
  `__xfs_inode_free` -> `call_rcu` -> `xfs_inode_free_callback` -> `kmem_cache_free`. list_empty()
  reliably means "not linked" on EVERY path except the one this fixes.
- Skipping a redundant add when already-linked is exactly as correct as performing it when
  not-linked: sb->s_inodes membership (not list POSITION) is what every walker (writeback, sync,
  drop_caches, pr_sweep) actually needs.

## Validation (RULE 4 step 2b: patch at proven cause, rebuild, reproduce, confirm)
1. Exact 3-test repro that broke sess5/sess6 (`dir_reuse_coherency fence_during_write
   fault_netpartition` @ 2/caw, MXFS_DEV=/dev/mapper/mpatha, live dmesg -T -w both nodes): **ALL 3
   PASS**, completed in ~300s total (previously: hung 600s+ on fault_netpartition alone, every
   time, across 2 sessions). Fix engaged (P141-SETUP-SKIP-DOUBLE-ADD) 7x on test2, ZERO
   P135-PRSWEEP-CYCLE, ZERO softlockups, ZERO P142.
2. Full 16-test (all of 2/caw's applicable suite except soak, which is a separate 1h+ duration
   test deferred to a later pass) run FRESH: **16/16 PASS** in 405s. Fix engaged 7x again, zero
   corruption signals.
3. Pre-fix baseline (SAME build lineage, diagnostic-only, run immediately before the fix): P141
   fired 5-7x, fault_netpartition FAILED, test2 hit the SAME `drop_pagecache_sb` softlockup
   signature (604s, `_raw_spin_unlock`/`pv_queued_spin_unlock` spin in `iterate_supers` walking
   `sb->s_inodes`) documented in every prior session (sess5, sess6, and this session's own pre-fix
   run) -- so this is a true before/after A-B comparison on the identical workload, not just "it
   passed once."

## IMPORTANT for next session: criteria.json is NOT reliable evidence of current state
`jq` summary showed ALL of 1/2/4/8/16/32-caw at "17/17 PASS, 0 FAIL" in criteria.json BEFORE this
session's fixes -- this is misleading. run.sh auto-updates criteria.json per-test as it runs, so it
accumulates a patchwork of timestamps from many different historical builds/sessions, NOT one
atomic full-suite run. The P141 corruption does NOT always fail the test it happens during (it
fires silently mid dir_reuse_coherency/fence_during_write in earlier runs THIS session while both
of those specific tests still reported PASS) -- it corrupts the list silently and only visibly
fails LATER when something else (drop_caches, pr_sweep) walks the corrupted list. So a per-test
"PASS" timestamp from an old build proves nothing about whether THIS bug was present then. Do NOT
treat criteria.json's current 100% figures as ground truth -- only trust FRESH full-suite runs
against the CURRENT build (0.10.94+). 4/caw's dir_reuse_coherency/fence_during_write/
fault_netpartition entries are dated 2026-07-07/07-11 (a week old) -- almost certainly predate
this fix and need re-validation, likewise 8/16/32.

## Next steps (exact, in order)
1. 1/caw fresh full 16-test suite (NOT just a spot-check -- the reset-for-create path has NO
   single-node exclusion guard, this bug CAN manifest at 1 node under solo churn, unlike most
   other mxfs multi-node bugs).
2. 4/caw, 8/caw, 16/caw, 32/caw fresh full 16-test suites, same methodology (live dmesg -T -w
   capture on ALL nodes at that scale, watch for P141-SETUP-SKIP-DOUBLE-ADD as confirmation the
   fix is engaging under that scale's churn too, zero P135/softlockup/BUG as the pass bar).
3. soak (1h+ duration test) for each node count -- deferred from the fast-suite passes above,
   schedule separately (can potentially run concurrently with other work, or in dedicated
   long-polling foreground chunks).
4. Once ALL 6 node counts show a FRESH, single-build-consistent 17/17 (16 fast + soak), the
   criteria "1/2/4/8/16/32 node caw dlm multipath test working 100%" is met -- write the
   criteria-met marker.
5. Diagnostic instrumentation left in place (P139, P141-SETUP-SKIP-DOUBLE-ADD, P142, all capped at
   200 occurrences) is cheap and harmless -- fine to leave for the remaining validation sweep as a
   confirming signal; can be stripped later if desired but not required for correctness.

## Files changed this session
- `pal/linux/xfs_iops.c`: xfs_setup_inode -- the actual fix (guarded inode_sb_list_add) +
  P141-SETUP-SKIP-DOUBLE-ADD diagnostic.
- `xfs/xfs_icache.c`: xfs_iget_recycle -- added P142-RECYCLE-STILL-LINKED diagnostic (else-branch
  of the existing sess6 P139 diagnostic-only revert; P139 itself left unchanged from sess6).
- `VERSION`: 0.10.91 (bad, deployed at sess6 handoff) -> 0.10.92 (rebuild of sess6's revert, no
  behavior change from source-reverted-but-unbuilt state) -> 0.10.93 (added P141/P142 diagnostics,
  no fix yet, used to PROVE the mechanism) -> 0.10.94 (the actual fix). **0.10.94 is the build to
  keep building on.**

## Escalation note
RULE 5's Fable/GPT chain was NOT needed this session -- own analysis (full lifecycle trace of
XFS_IRECLAIMABLE's single setter, the slab ctor, the two xfs_setup_inode call sites, live stack
trace via targeted dump_stack) found and fixed the root cause without a consult. sess6 had queued
"escalate to GPT next" but that turned out unnecessary -- the P139-based framing GPT/Fable would
have been fed was itself backwards, so a fresh diagnostic angle (instrument the actual call site,
not one step removed) was more valuable than continuing to reason about the wrong signal.
