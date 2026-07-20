---
name: ccloop703f-sess1-ROOT-FIXED-bast-demoter-cleared-before-irele
description: ROOT CAUSE + FIX for P-DBLRECLAIM/fence_during_write@8caw soft lockup: i_dlm_demoter cleared before trailing xfs_irele/iput lets nested ilock self-de…
metadata:
  type: project
---

## Context

Criteria: "1/2/4/8/16/32 node caw dlm multipath test working 100%" (ccloop, many
sessions since 2026-06-01). Before this session, the ENTIRE ladder was 100% PASS
fresh EXCEPT 8/caw: `dir_reuse_coherency`+`fence_during_write` PENDING (mid-repro)
and `fault_netpartition` FAIL (nodes_pass=0/8, NO_TERMINAL_RECORD=8 — almost
certainly a cascade from this same wedge; run.sh:449 shows that status just means
the node's RESULT: line never printed within the ssh timeout, i.e. the node hung).
1/2/4/16/32 all already fresh-verified 17/17 (see memory
`AAA-ccloopff21-sess1-32caw-COMPLETE-17of17` and prior sessions).

Inherited from ff214062 sess1 (5d15dafe): a live soft-lockup repro was mid-flight
(`scripts/repro_dblreclaim.sh 8 15 dir_reuse_coherency`, chains a dir_reuse_coherency
warmup immediately into fence_during_write in ONE cluster session — isolated
fence_during_write alone never reproduced it in 15 iters). xfs_icache.c already had
a P-DBLRECLAIM pr_warn on `xfs_inode_mark_reclaimable`'s
`ASSERT_ALWAYS(!xfs_iflags_test(ip, XFS_ALL_IRECLAIM_FLAGS))` and holder-stamp
fields on `pag_ici_lock` (only 6 of 19 real acquire sites stamped).

## What this session did

1. Extended `pag_ici_lock` holder-stamping to ALL 19 acquire sites (was 6):
   xfs_icache.c (6), xfs_mxfs_dlm.c (10), pal/linux/xfs_buf.c (3). New
   `mxfs_ici_lock(pag)` wrapper (xfs_icache.c, declared in xfs_icache.h) = spin_lock
   equivalent (spin_trylock + cpu_relax loop, so IDENTICAL locking semantics) that
   also stamps pid/comm/jiffies and prints a rate-limited "P-ICI-STUCK" if a waiter
   spins >5s. Purely diagnostic, safe everywhere the old spin_lock was (incl. the
   evict-ring callback's must-not-block context — trylock+cpu_relax doesn't sleep).
2. Wrote `scripts/harvest_dblreclaim.sh <N> [since-utc]` — aggregates P-DBLRECLAIM /
   P-ICI-STUCK / soft-lockup / Call-Trace evidence across N nodes, D-state task
   snapshot, and a LOCAL python pairing pass over P25-INSTR sync-inactive/-DONE
   lines per node (P25-INSTR fires on every unlinked-inode reclaim — 1000s of
   lines/run even healthy, so never dump verbatim; instead flag any ino with an
   unmatched/dangling start = the actual stuck call, or a 2nd start before the 1st
   DONE = true overlapping double-entry). EVICT-RING-* also counted-only (routine,
   1000s/run).
3. Relaunched the repro loop → hit on iter 2 within ~15 min. Harvested LIVE:
   - test3 kworker `kworker/u12:20+mxfs-ino-bast/dm-1` PID 11046, D-state, growing
     monotonically past 1000s (permanently stuck, not slow).
   - `/proc/11046/stack` (live, direct kernel stack read via ssh):
     `mxfs_dlm_ilock_begin+0xbb0/0x3c50 <- xfs_ilock <- xfs_attr_inactive <-
     xfs_inactive <- xfs_inode_mark_reclaimable <- xfs_fs_destroy_inode <-
     destroy_inode <- evict <- iput <- xfs_irele <- mxfs_dlm_bast_work_fn <-
     process_one_work <- worker_thread <- kthread`
   - dmesg on the SAME PID moments earlier: kernel `WARNING: ... at fs/inode.c:451
     ihold+0x28/0x40` (twice, once on PID 12086 too) — ihold()'s own
     `WARN_ON(atomic_inc_return(&i_count) < 2)` fires when i_count was already ≤0
     pre-increment. Traced to `mxfs_dlm_ilock_end.part.0`'s `ihold(VFS_I(ip))`
     call in the `need_flush` branch (deferred-BAST-to-workqueue path).

## Root cause (proven, not guessed)

`mxfs_dlm_bast_work_fn` / `mxfs_dlm_bast_dwork_fn` / (the mxfs_trans_drain_inode_unlocks
pairing) all did:
```
ip->i_dlm_demoter = current;
mxfs_dlm_bast_process(ip);
ip->i_dlm_demoter = NULL;      // <-- cleared too early
xfs_irele(ip) / iput(...);      // <-- can be the LAST ref
```
If that trailing ref-drop is the last reference, it cascades SYNCHRONOUSLY into
`evict -> destroy_inode -> xfs_inode_mark_reclaimable`'s MXFS synchronous-inactivation
path `-> xfs_inactive -> xfs_attr_inactive`, which takes its OWN `xfs_ilock`/
`xfs_iunlock` on the SAME `ip`. `mxfs_dlm_ilock_begin`'s own wait loop
(~xfs_mxfs_dlm.c:20927) is EXPLICITLY designed to exempt this:
```
while ((state == DEMOTING || ACQUIRING || BAST) && ip->i_dlm_demoter != current) { ... }
/* comment: "Demoter is exempt (it must re-enter during its own drain)" */
```
— several other gates in the same function (P79-NESTADMIT, the relflush fast path)
also check `demoter != current` for the identical reason. But because demoter was
already NULL by the time the cascade reaches this nested lock, none of those
exemptions fire; the nested acquire is treated as a brand-new external cross-node
request and blocks — forever, since the peer that receives the lock we just BAST-
released has no reason to give it back, and this very thread was the one meant to
finish driving the release. Self-deadlock. This also explains the original
P-DBLRECLAIM framing (a second logical actor touching the same inode's lifecycle
while it's wedged) and the multi-CPU soft lockup (this kworker parks permanently;
anything else needing `pag_ici_lock`/this inode's ILOCK backs up behind it).

One sibling site (`xfs_mxfs_dlm.c` P60-EDEADLK-FREEING inline branch, ~21382) does
this correctly — no trailing ref-drop after clearing demoter there (igrab() already
failed, nothing to release) — confirms the intended pattern and that this is a
narrow, mechanical bug, not a design-level one.

Audited ALL 5 `i_dlm_demoter = current` sites in xfs_mxfs_dlm.c: 3 had this bug
(fixed below), 1 (P60-EDEADLK-FREEING) has no trailing ref-drop so is fine, 1
(P72-ORPHAN-FORCEREL, ~15022) uses demoter purely as a mutex-claim flag around pure
DLM-state bookkeeping with no VFS ref-drop — different pattern, not affected.

## Fix (0.10.76, srcversion EAB3334D0AA6A8139C0E838)

Moved `ip->i_dlm_demoter = NULL;` to AFTER the trailing ref-drop in all 3 real
occurrences:
1. `mxfs_dlm_bast_work_fn` (xfs_mxfs_dlm.c ~13883): demoter=NULL moved past the
   sess60-detector's `xfs_irele(ip)`.
2. `mxfs_dlm_bast_dwork_fn` (~14030, MHT timer expiry): demoter=NULL moved past
   `xfs_irele(ip)`.
3. `mxfs_trans_drain_inode_unlocks` (~28177): demoter=NULL moved past
   `iput(VFS_I(ip))`.

No other logic changed — purely reordering one statement per site to extend an
already-designed exemption window to cover the call that can trigger the re-entrant
cascade.

## Status as of this write

Fix built (0.10.76). test3's wedged kworker was NOT recoverable (D-state kthread,
unkillable — needed `virsh -c qemu:///system destroy/start test3`, RULE 2 permits
test-VM cycling). All 8 nodes confirmed clean post-cycle. Relaunched
`scripts/repro_dblreclaim.sh 8 15 dir_reuse_coherency` against the fixed build —
validation IN PROGRESS, not yet confirmed clean. **Next session: check
`/tmp/claude-1000/-src-mxfs/80927ebf-ec69-4017-b901-82ed8c350b63/scratchpad/repro_fix_validate.log`
first** (or wherever the current session's scratchpad landed it) for the outcome.
If clean across all 15 iters (or a good sample, e.g. 5+ with the prior hit rate of
~1-in-2), proceed to: fix `fault_netpartition` cascade (re-run fresh, expect it to
just pass now), then the FULL fresh single-build revalidation sweep of 1/2/4/8/16/32
on 0.10.76 via `scripts/revalidate_cell.sh` per node, then
`python3 scripts/matrix_check.py --since <0.10.76-build-epoch>` (no --nodes filter)
as the honest YES gate — every one of 1/2/4/8/16/32 @ caw must show 17/17 PASS
(fresh) before writing YES to the criteria-met marker. If the repro loop hits AGAIN
on the new build: re-harvest via `scripts/harvest_dblreclaim.sh 8 <since-utc>`,
re-open RULE-4 loop (this fix may be necessary-but-not-sufficient — there could be
a second, rarer contributing bug given only one hit was captured so far).
