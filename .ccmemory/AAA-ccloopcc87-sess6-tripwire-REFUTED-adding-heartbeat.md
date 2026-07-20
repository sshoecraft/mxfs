---
name: AAA-ccloopcc87-sess6-tripwire-REFUTED-adding-heartbeat
description: sess6: sweep-pin tripwire fired ZERO times despite 600s+ hang recurring — refutes GPT's over-release-via-eviction hypothesis. Added heartbeat (0.10.8…
metadata:
  type: project
tags: [ccloop-cc87fed3, pr_sweep, build-0.10.89, RULE4]
---

## Tripwire result (build 0.10.88, srcversion FFDCAF770F96A9DC034EC4D) — NEGATIVE

Implemented GPT's decisive experiment exactly as designed: `mp->m_mxfs_pr_sweep_pinned` (new field,
xfs_mount.h) tracks which `struct inode *` `mxfs_dlm_pr_sweep_work_fn`'s `toput` variable currently holds a
live `igrab()` reference on (set/cleared via WRITE_ONCE around every igrab/iput site — 5 sites total: cycle
bailout, cap bailout, main loop reassignment, shutdown-abort, final natural exit). Checked via READ_ONCE at
the TOP of `xfs_inode_mark_reclaimable` (xfs_icache.c, earlier/more-complete than the originally-suggested
P25-INSTR site — this one catches BOTH the sync-inactive and async inodegc-queue paths) with a
P136-SWEEPPIN-TRIPWIRE pr_warn + dump_stack() if it ever matches.

Re-ran the exact repro (`MXFS_DEV=/dev/mapper/mpatha ./run.sh 2 caw dir_reuse_coherency fence_during_write
fault_netpartition`, live dmesg -T -w on both nodes). dir_reuse_coherency PASS, fence_during_write PASS,
fault_netpartition FAILED — SAME hang reproduced (test2, `_raw_spin_lock` on `s_inode_list_lock` via
`drop_pagecache_sb`, `bash` task, this time CPU#3 not CPU#1, climbing past 599s before I stopped watching).
**P136-SWEEPPIN-TRIPWIRE fired ZERO times on either node, for the entire hang.** This is strong negative
evidence: GPT's specific hypothesis (an inode pr_sweep believes it holds via igrab gets prematurely evicted
by an over-release elsewhere) is REFUTED, at least for this hook location. Do not re-attempt this exact
experiment without a new reason to believe the hook placement was wrong.

## New finding from the SAME capture: pr_sweep goes completely silent 28s before the hang starts
All 6 P135-PRSWEEP-CYCLE hits this run landed between 03:34:03 and 03:34:25 (short cycles, visited=2-3,
same as sess6's first 0.10.87 validation — ring buffer bailout still works correctly). The softlockup started
at 03:34:53 (28s later). **Zero `mxfs:` log lines of ANY kind appear for the entire 600s+ hang** (confirmed:
`awk` window from softlockup-start to end of capture, `grep -c "mxfs:"` = 0). Since pr_sweep is the ONLY mxfs
code touching `s_inode_list_lock` (re-confirmed via grep across xfs/*.c, pal/linux/*.c, mxfs_clayer/*.c), this
leaves two live possibilities, NOT yet distinguished:
(a) pr_sweep is not running at all during the hang (something else — necessarily 100% stock upstream kernel
    code, e.g. another `drop_caches` caller, a shrinker, `evict_inodes`, `sync_filesystem` — is the true
    holder, walking the SAME corrupted list structure with ZERO cycle protection since it's unmodified
    upstream code mxfs doesn't fork), or
(b) pr_sweep IS running, silently mid-walk, and just hasn't hit ANY of its own log points yet — no P135 (cycle
    not yet within the trailing-32 window), not yet at the 1M P-PRSWEEP-CAP, and not yet at natural
    completion (which was ALSO silent before this session's changes when swept==0 — FIXED this session, see
    below).

## Also confirmed: a fresh SSH login to the wedged node hangs too (both times, ~600-800s in)
`nc test2 22` gets the SSH banner INSTANTLY (TCP/sshd listener fine) but an authenticated interactive session
times out even with `ServerAliveInterval=3 ServerAliveCountMax=2` (~6s bound) — "Timeout, server test2 not
responding." The PRE-EXISTING `dmesg -T -w` stream keeps flowing throughout (proves the node isn't fully
frozen, just something about NEW session/process setup also stalls). This means: once the hang starts, you
get ONE shot at live interactive diagnosis (whatever session you already have open) — you cannot open a new
SSH session mid-hang to run `sysrq` or check `/proc` state. Any diagnostic you want data from during a live
hang MUST be pre-instrumented in the kernel module (log lines), not attempted interactively after the fact.

## Instrumentation added this session in response (build 0.10.89, srcversion 0FD654C94C163C7FB8EF6BC)
Since a NEW ssh session can't be opened mid-hang, added logging that will show up in the ALREADY-STREAMING
dmesg capture to settle (a) vs (b) above on the next repro, all in `mxfs_dlm_pr_sweep_work_fn`
(xfs_mxfs_dlm.c):
- `P137-PRSWEEP-ENTER` — unconditional pr_warn at function entry (after the shutdown/unmounting check). Safe
  from flooding: `mxfs_dlm_pr_sweep_trigger` rate-limits to at most 1 queue per 3000ms via jiffies cmpxchg, so
  this is bounded to ~1 line/3s max.
- `P137-PRSWEEP-HEARTBEAT` — `pr_warn_ratelimited` at every `force_yield` boundary (every
  MXFS_PRSWEEP_YIELD_EVERY=2048 visits) inside the walk loop. Deliberately rate-limited (NOT plain pr_warn)
  because if the corrupted structure creates a walk far longer than the real (~thousands-entry) inode cache,
  2048-visit spacing could otherwise fire thousands of times/sec and flood the log.
- `P137-PRSWEEP-EXIT` — made the natural-completion path log unconditionally (previously SILENT whenever
  swept==0, i.e. every normal run with no idle PR grants to release — which was probably ALWAYS in practice,
  meaning pr_sweep's own successful completions have likely never been visible in ANY prior session's captures).

## Next step
Re-run the identical repro on 0.10.89 with live dmesg streaming. Read the P137 lines during/around the next
hang:
- If ENTER appears with no matching EXIT/bailout for the duration of a hang, AND heartbeats keep incrementing
  `visited` far past a normal small count → CONFIRMS pr_sweep itself is the long-running walker (points at:
  the corruption creates an effectively-unbounded or >32-length chain the ring buffer can't catch; the real
  fix is Floyd's cycle detection, O(1) memory, catches ANY length — see prior memory
  `AAA-ccloopcc87-sess6-ringbuf-INSUFFICIENT-worse-hang-need-tripwire` for the exact algorithm sketch and why
  a bigger fixed ring doesn't work).
- If NO new ENTER appears at all once the hang starts (pr_sweep simply isn't retriggering) → the true holder
  is stock kernel code outside mxfs's control at the `s_inode_list_lock` layer; the fix has to be about
  PREVENTING the list corruption from ever occurring in the first place (find the actual over-release/corrupt
  write, likely still somewhere in the BAST/reference-counting graph, same general family as BUG3 but a
  different site — e.g. the two still-unaudited raw-ihold candidates noted in the sess5 memory:
  `mxfs_dlm_ilock_begin`'s P-DEMWAIT-REDRIVE site ~21283, `mxfs_dlm_queue_pr_demote` itself ~26802), not about
  bounding any one consumer's walk.

## Cluster state
test1+test2 freshly reset and on 0.10.89 (ALL_OK) as of this checkpoint, about to re-run the repro.
