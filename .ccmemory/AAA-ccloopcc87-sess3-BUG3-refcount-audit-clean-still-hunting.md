---
name: AAA-ccloopcc87-sess3-BUG3-refcount-audit-clean-still-hunting
description: ccloop cc87fed3 sess3: exhaustive audit of bast_notify/bast_process/bast_dwork_fn ref-counting found NO single-point bug — bug3 is likely a genuine r…
metadata:
  type: project
---

## Context
Continues from `AAA-ccloopcc87-sess3-TWO-FIXES-caw-granted-mode-and-dwork-badref`
(FIX6 CAW granted-mode, FIX7 dwork phantom-ref guard — both PROVEN, both now
validated 3/3 clean iterations for fence_during_write@8/caw). This memory covers
the THIRD bug found during that same validation: a rarer (1-in-4 full-combo
iterations so far) `VFS_BUG_ON_INODE(I_FREEING|I_CLEAR)` crash inside `iput()`,
hit via `rm -> do_unlinkat -> iput` (test7, iteration "caw84_iter2") — SAME
assertion/RIP offset (`iput+0x1c5/0x250`) as FIX7's bug, but through a call site
FIX7 cannot guard (plain kernel unlink path, not mxfs code).

## What's been done
1. Added `P125-EVICT-SUSPECT` diagnostic in `mxfs_dlm_evict()` (very start of the
   function, before any other logic) — fires (capped 5000) whenever VFS evict()
   is entered while mxfs's own bookkeeping (`i_dlm_demoter`, `i_dlm_ex_holders`,
   `i_dlm_pr_holders`, `i_dlm_pin_count`, `i_dlm_bast_pending`) is NOT fully
   quiescent — logs mode/state/all-those-fields/i_count/i_state/comm. Build
   `1C072D882738A82FFD94E32` (diagnostic-only, no behavior change, VERSION not
   bumped from 0.10.84 for this — bump when the eventual real fix lands).
2. Ran 2 more full-combo iterations (`caw84_iter3diag`, `caw84_iter4diag`) — BOTH
   clean (RUN_EXIT=0, 8/8 both sub-tests, 0 D-state, 0 crashes, P125 never fired
   — useful as a confirmed-no-false-positive baseline for the diagnostic itself).
   That's 3/3 clean for FIX6+FIX7 as a pair — satisfies RULE 4 for THAT chain.
3. Ran 15 rapid `fence_during_write`-ONLY iterations (`tests/repro_fdw_only_loop.sh`,
   new reusable RULE-3 script, `<N> <iters> <outdir>`, stops early on any
   invalid-opcode/kernel-BUG/P125/P124 hit) — ALL 15 clean. **Confirms bug3 needs
   `dir_reuse_coherency`'s prior churn as a precondition — `fence_during_write`
   alone (even 15x back-to-back) never reproduces it.** Root cause: `run.sh`
   does a FRESH `mkfs` every single invocation (tests/setup/prep_fs.sh, called
   unconditionally in `prep()` around run.sh:242-244) — there is NO way to "prime"
   the cluster with dir_reuse_coherency's churn and then cheaply re-attempt just
   fence_during_write against that same state; every attempt pays full mkfs+mount
   cost, and only the FULL combo (dir_reuse_coherency immediately followed by
   fence_during_write in ONE run.sh invocation) has ever hit bug3.
4. **Exhaustively audited reference-counting in the 3 prime suspects — found NO
   single-point bug (no missing `ihold`, no missing `return` causing double-irele,
   no internal double-drop) in any of them:**
   - `mxfs_dlm_bast_notify()` (xfs_mxfs_dlm.c ~14871-15630, full function read
     top to bottom this session): takes its own entry ref via
     `xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0, &ip)` (upstream-safe, uses
     `igrab()` internally which correctly rejects a racing-eviction inode — NOT
     the bug). Every one of its ~11 exit paths either (a) explicitly
     `ihold()`s-then-`queue_delayed_work()`-else-`irele()`s for a SEPARATE
     dwork-arm ref (2 sites, both correctly paired), or (b) transfers its OWN
     entry ref to a queued work/dwork item with a "do NOT irele, work fn owns
     it" comment + bare `return` (5 sites, e.g. line ~15615 for the
     "BRANCH=immediate" no-holders case), or (c) explicitly `xfs_irele(ip)`s its
     own entry ref before returning (the remaining ~6 sites, incl. the final
     fall-through "active holders — defer to unlock path" case at the very end
     of the function, which correctly has no `return` since it's already the
     last statement in a void function). All paths individually balanced.
   - `mxfs_dlm_bast_process()` (10974-13964, read in full across 2 sessions):
     contains exactly 2 of its OWN `xfs_irele(ip)` calls, both the standard
     "already armed, drop my redundant ihold()" pattern (lines that were
     ~12380 and ~13888 pre-FIX7-insertion), BOTH correctly preceded by their own
     `ihold(vip)`. Never touches/drops a CALLER's outer reference. Confirmed via
     `awk` scan of the function's exact line range for every `xfs_irele`/`iput(`
     occurrence — only those 2, both clean.
   - `mxfs_dlm_bast_dwork_fn()`: now guarded by FIX7 (`mxfs_dlm_dwork_safe_irele`)
     at all 4 exit paths; internally consistent (exactly 1 irele-or-skip per
     invocation).
   - All 10 external `ihold()`-then-`queue_delayed_work()`-else-`irele()` call
     sites for `i_dlm_bast_dwork` across the whole file (already audited sess3
     earlier, see the FIX6/FIX7 memory) — all correctly paired.
   - `xfs_iget_cache_hit()`'s `XFS_IGET_INCORE` path (xfs_icache.c ~1170-1225):
     standard upstream-shaped logic (`igrab()` / `xfs_ilock_nowait` +
     `XFS_IRECLAIM` tagging for the reclaimable-recycle path), not obviously
     divergent from safe upstream XFS behavior — did not find a bug here either.

## Working hypothesis (UNPROVEN — needs P125 or a live capture to confirm)
Given no static single-point bug found across the 3 prime suspects, this is very
likely a genuine TIMING RACE between two or more of the many concurrently-runnable
paths on the SAME inode under extreme hot-dir churn (the fence_during_write shared
`$HOT` dir, hammered by all N nodes with rapid create+immediate-delete on a tiny
16-name-per-rank keyspace) — e.g. bast_notify's "BRANCH=immediate" transferring its
entry ref to `mxfs_dlm_bast_work_fn` at the EXACT moment something else
(xfs_reclaim_inode / `mxfs_dlm_evict`, or a DIFFERENT bast_notify re-entry for the
SAME inode number after a fast create-delete-recreate cycle) also believes it owns
a droppable reference to what it thinks is the same inode identity, but the
identity has ALREADY been recycled. This codebase has EXTENSIVE prior history of
"reused inode" edge cases (see memory `caw-sess5-STALER-identified-reload-inode-and-levers-tried`
re: `mxfs_dlm_reload_inode` on reused-inode grant) — worth reading that memory in
full if resuming this hunt, it may already contain relevant analysis of the same
general hazard class.

NOTE (important correction from an earlier over-read this session): the P72/PW-
RELFENCE/P138 dmesg lines that appeared TEMPORALLY NEAR the crash (all for
ino=10487682, a directory) are almost certainly NOT causally related to the crash
— they're from a DIFFERENT comm (`kworker/u10:29`) than the crashing thread
(`rm`, PID 8688), just interleaved in the shared dmesg ring buffer from a busy
8-node system. Don't re-chase that specific inode's activity as the crash's
direct cause without new evidence tying them together.

## State as of this write
- Iteration 5 (full combo, `caw84_iter5diag` outdir) LAUNCHED, in progress, same
  P125-instrumented build (1C072D882738A82FFD94E32). Check
  `/tmp/claude-1000/-src-mxfs/8c458175-2c0a-4277-9e01-6e076b387b26/scratchpad/caw84_iter5diag/`
  (monitor.log / run.log / .done) for outcome — or if that scratchpad is gone
  (new session, new scratchpad path), just relaunch fresh:
  `tests/diag_cpu_pin_capture.sh 8 <outdir> caw_fair_handoff=1`.
- **Next action if P125-EVICT-SUSPECT fires**: read the exact field values it
  logs (demoter/ex/pr/pin/bast_pending/i_count/i_state/comm) — that alone should
  narrow the culprit mechanism enormously (e.g. demoter!=NULL means a bast_process
  instance's OWN in-flight drain still thinks it owns this inode; bast_pending=1
  means a dwork/rearm was never consumed; ex/pr>0 means a local op's holder count
  never got decremented). Cross-reference against whichever of bast_notify's exit
  branches matches that state shape (I now have the FULL function read and
  annotated above — use it as a map rather than re-reading from scratch).
- **Next action if 3-4 more iterations stay clean**: consider whether the P125
  diagnostic's mere PRESENCE (extra pr_warn + atomic_inc_return on every eviction)
  perturbs timing enough to mask the race (a classic heisenbug risk) — if so, may
  need a LOWER-overhead detector (e.g. only sample 1-in-N evictions, or use a
  static per-CPU counter instead of atomic, or move the check to only fire when
  i_count looks suspicious rather than every eviction) to avoid accidentally
  papering over the race by slowing down the exact codepath that creates it.
- Do NOT forget: FIX6+FIX7 are independently proven and validated (3/3 clean) —
  if bug3 hunting runs long, it is legitimate to write these up as durable
  progress even before bug3 itself is closed. The criteria as a whole still needs
  bug3 fixed (or proven unreachable / sufficiently mitigated) before any 1/2/4/8/
  16/32 sweep can be trusted, since it manifests as a hard crash + cluster
  timeout, not just a slow/flaky result.
