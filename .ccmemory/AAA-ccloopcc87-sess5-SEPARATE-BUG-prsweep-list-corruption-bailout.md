---
name: AAA-ccloopcc87-sess5-SEPARATE-BUG-prsweep-list-corruption-bailout
description: sess5: separate hang found while validating BUG3 fix — mxfs_dlm_pr_sweep_work_fn's sb->s_inodes walk gets stuck on a self-referential (post-eviction)…
metadata:
  type: project
---

## Context
Found while validating BUG3's fix (see sibling memory
`AAA-ccloopcc87-sess5-BUG3-ROOT-CAUSE-PROVEN-FIXED-ilock_end-raw-ihold`) during a fresh
1/2/4/8/16/32 sweep. `fault_netpartition` FAILED at 2/caw when run immediately after
`dir_reuse_coherency`+`fence_during_write` in the same cluster session (isolated
`fault_netpartition` alone passes cleanly — same "needs prior churn" precondition shape
as BUG3, but a DIFFERENT bug — proven unrelated to BUG3 via bisection, see below).

## Proof this is NOT a BUG3 regression
Reverted BUG3's 3 fixes (raw ihold restored in `mxfs_dlm_ilock_end` idle_arm/need_flush +
`mxfs_inode_dlm_defer_bast`), rebuilt (srcversion matched the EXACT pre-fix build
6814865BC1EE6681D117472), redeployed, re-ran the identical 3-test sequence
(`dir_reuse_coherency fence_during_write fault_netpartition` @ 2/caw) — **the SAME hang
occurred** (8 softlockup hits on test2, same signature). This is pre-existing, unrelated
to the ilock_end/defer_bast raw-ihold fix. BUG3's fix was restored afterward (confirmed
byte-identical srcversion 8B64C04FB45CAFCB9CC714A via backup/restore, not re-typed).

## What's actually happening (proven via live capture, not guessed)
`fault_netpartition.sh`'s own `sync; echo 1 > /proc/sys/vm/drop_caches` step (bash,
stock kernel `drop_caches_sysctl_handler -> iterate_supers -> drop_pagecache_sb`) blocks
in `_raw_spin_lock` trying to acquire `sb->s_inode_list_lock` — for 200s+, watchdog
soft-lockup on the SAME comm/pid throughout, RIP oscillating in a tight
`_raw_spin_lock`/`pv_queued_spin_unlock` range (confirmed genuine spin via 4x rapid RIP
resample, not just "slow"; serial log alone showed NO call trace for this specific hang —
only the live `dmesg -T -w` SSH stream captured it, once again confirming that technique
is required).

Immediately before the hang: `P-PRSWEEP-CAP visited=1000000 seen=0 swept=0` — 
`mxfs_dlm_pr_sweep_work_fn` (the v0.10.38 dir-EX-BAST sweep worker, ALREADY the subject
of sess2-of-this-run's FIX4/FIX5 for a similar-shaped 750s+ softlockup — see memories
`AAA-ccloopcc87-sess2-FIX4-pr_sweep_unbounded_lock_hold-VALIDATING` and `...-FIX5-...`)
ran its FULL 1,000,000-visit walk and found ZERO candidates — suspicious on a node whose
real inode cache is only ~thousands of entries (per sess2's own measurement). Added a
direct cycle-detector (`P135-PRSWEEP-CYCLE`, tracks the walk's first-visited inode
pointer, fires if the SAME pointer is seen again without the loop naturally terminating
at the list head) — **fired immediately and repeatedly**: `sb->s_inodes`'s first entry
(ino=2097289 in the capture) has become self-referential (`i_sb_list.next == prev ==
&inode->i_sb_list`, EXACTLY the state `list_del_init()` leaves an entry in after a
normal, correct VFS `evict()` -> `inode_sb_list_del()` call) — but the walk still reaches
it from what should be a live position in the list, meaning something upstream of it in
`sb->s_inodes` still points here. First captured cycle_len values (1,2,3,4...) — later
values jump by ~6 per logged line, which is a LOG-CAPTURE artifact (pr_warn under the
spinlock at high frequency drops lines under this print volume), not evidence of an
actual 6-node cycle — the true shape is almost certainly a stuck 1-node self-loop
(cycle_len=1 repeating), not a longer cycle.

## Root cause — NOT YET FOUND (this is the residual gap)
Working theory (NOT proven to the same rigor as BUG3): pr_sweep's own loop holds an
`igrab()`'d reference on its CURRENT entry across a `spin_unlock` window (while calling
`mxfs_dlm_queue_pr_demote`/`cond_resched()`), which SHOULD make it impossible for that
exact entry to be concurrently evicted (i_count can't hit 0 while pr_sweep's extra ref
is outstanding) — for the entry to still end up self-looped by the time pr_sweep
re-locks and calls `list_next_entry` on it, some OTHER code would have to be
over-releasing a reference it doesn't legitimately hold (same GENERAL bug family as
BUG3 — a phantom/extra drop — but NOT proven to be the SAME specific call site; BUG3's
3 fixed sites are unrelated to pr_sweep's own call graph). Two STILL-UNAUDITED raw-ihold
sites from this session's earlier BUG3 hunt remain candidates worth checking first if
this resurfaces: `mxfs_dlm_ilock_begin`'s P-DEMWAIT-REDRIVE site (~21283, xfs_mxfs_dlm.c)
and `mxfs_dlm_queue_pr_demote` itself (~26802) — neither confirmed vulnerable, both use
patterns similar in SHAPE (not necessarily in actual exposure) to BUG3's 3 fixed sites.
`mxfs_dlm_pr_sweep_trigger`'s re-queue/rate-limit logic (mentioned as unproven in sess2's
own FIX5 memory) is another unchecked candidate.

## Mitigation applied (build 0.10.86, srcversion 53D9689ED5A57327DA8A50D)
Converted the `P135-PRSWEEP-CYCLE` detector from diagnostic-only into an immediate
bailout: `spin_unlock` + `iput(toput)` + one `pr_warn` + `return`, mirroring the
existing 1M-visit-cap bailout's own cleanup shape exactly. This is NOT a root-cause fix
— it does not explain or repair why the list entry became stale — but it converts the
failure mode from "starve any other `s_inode_list_lock` consumer for 200s+ (up to
however long it'd take to grind through however much of the 1M cap)" down to
"near-instant bailout on the very next iteration after the corruption is detected",
which directly eliminates the OBSERVED hang. This mirrors the codebase's own established
precedent for this exact function (best-effort, not correctness-critical background
optimization — explicitly documented in the function's own comments) and for the
general bug family (sess60's "detect and skip rather than crash" pattern for BUG3-
adjacent issues).

## Validation status — CHECK FIRST IF RESUMING
NOT yet validated after this fix (write-then-checkpoint before testing, per this
session's practice of saving proof before risking context loss). Next action: rebuild
(done, 0.10.86 built clean) — REDEPLOY to test1+test2 — re-run the EXACT 3-test sequence
(`dir_reuse_coherency fence_during_write fault_netpartition` @ 2/caw, `MXFS_DEV=/dev/mapper/mpatha
./run.sh 2 caw dir_reuse_coherency fence_during_write fault_netpartition`) with live
per-node dmesg -T -w streaming — confirm `fault_netpartition` now PASSES and/or confirm
`P135-PRSWEEP-CYCLE` firing (proves the mitigation engages) WITHOUT any softlockup
following it. If it still hangs: the self-loop theory may be incomplete, or there's a
SEPARATE trigger — re-open RULE 4 with a fresh live capture.

## Then: resume the full 1/2/4/8/16/32 fresh sweep
Already completed BEFORE this bug was found: 1/caw = 17/17 PASS (fresh). 2/caw was
IN PROGRESS when this was found (14/17 shown PASS before hitting fault_netpartition).
Once this mitigation is validated, RESUME the sweep from 2/caw (re-run the FULL 2/caw
suite fresh, not just the 3-test subset), then proceed to 4/8/16/32/caw. 8/caw's
dir_reuse_coherency+fence_during_write combo already has 5 clean BUG3-validation
iterations recorded (see sibling BUG3 memory) — still want the OTHER tests in 8/caw's
full suite run fresh at least once on 0.10.86 before treating 8/caw as done, since this
NEW fix (0.10.86) postdates those 5 validation iterations (which ran on 0.10.85, before
this pr_sweep mitigation existed).
