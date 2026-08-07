---
name: ccloop-c7ee71c6-sess25-demoter-claim-clobber-ROOT-FIXED
description: ROOT PROVEN+FIXED: dwork release drain overwrote+cleared work drain's i_dlm_demoter claim -> permanent self-wedge. Claim is now owned+nestable (cmpxc…
metadata:
  type: project
tags: [demoter, wedge, bast, rule4, rule5, gpt, node_responsive]
---

# sess25: D-BAST-IRELE-INACTIVE-SELF-WEDGE — ROOT PROVEN, FIXED, VERIFIED

## Symptom

Permanent single-node wedge, 3 of 32 nodes at once, identical stacks, etime
619–839s and CLIMBING, on a **quiesced** cluster:

    mxfs_dlm_ilock_begin <- xfs_ilock <- xfs_attr_inactive <- xfs_inactive
    <- xfs_inode_mark_reclaimable <- xfs_fs_destroy_inode <- destroy_inode
    <- evict <- iput <- xfs_irele <- mxfs_dlm_bast_work_fn

    P73-WAITSTALL ino=... req=5 mode=3 state=3 ex=0 pr=0 pin=0
                  bast_pend=0 work_busy=2 relflush=1

## Root cause — read off the ring, not inferred

`i_dlm_demoter` was an unqualified single-slot `task_struct *` shared by every
release path. The new claim ring replayed it:

    SET   line=15980 pid=59368 cookie=446   <- bast_work_fn claims
    SET   line=16280 pid=56068 cookie=449   <- bast_dwork_fn OVERWRITES it
    CLEAR line=16292 pid=56068 cookie=450   <- and unconditionally CLEARS it
    WAIT  line=25206 pid=59368 cookie=451   <- 59368 parks, demoter_pid=0

`mxfs_dlm_bast_work_fn` and `mxfs_dlm_bast_dwork_fn` ran drains on the SAME
inode concurrently. The dwork stole the slot and NULLed it on exit. The work
fn's trailing `xfs_irele` — the last ref — cascaded into inactivation, re-took
the inode lock, found the slot NULL instead of itself, lost the "demoter is
exempt (it must re-enter during its own drain)" exemption, and parked forever
on a release only it could drive.

## Refuted FIRST, by their own probes reading zero — do not re-chase

- **P72 orphan-reclaim demoter override** (`P72-DEMOTER-OVERRIDE` = 0 on all
  wedged nodes). Attractive because it is a 10s "leaked demoter" heuristic that
  could create the state it detects. It did not fire.
- **EDEADLK-freeing self-clobber** (`P60-EDEADLK-FREEING` = 0). Same task does
  SET_DEMOTER / drain / demoter=NULL then retries into the demote-wait —
  statically real, never executed.

## Fix (v0.11.210) — claim is OWNED and NESTABLE

- `MXFS_SET_DEMOTER`: `cmpxchg` claims only an unowned slot, or re-claims its
  own (depth++). **Never overwrites a foreign live claim.**
- `MXFS_CLEAR_DEMOTER`: only the owner releases; only the outermost level
  clears.
- cmpxchg, not `i_dlm_lock`: call sites disagree about whether that spinlock is
  held, so taking it inside the macro would deadlock some callers.
- New probe `P74-DEMOTER-CONTEST` names a refused steal.

## Verified — and the fix path was EXERCISED, not merely absent

Before: dirent_durability FAIL 31/32 (durable_loss=8) + node_responsive FAIL
31/32 (dstate=1). After, same workload: **both PASS 32/32**, durable_loss=0,
dstate=0 — with **72 P74-DEMOTER-CONTEST** cluster-wide (age_ms=1, distinct
holder_line 16350 vs 16050), i.e. 72 real concurrent drains refused.

## The detector that found it — node_responsive was measuring LOAD

`node_responsive.sh`'s D-state check was a single instantaneous `ps` snapshot,
and the script **manufactures that load itself** (all N ranks mkdir+rmdir into
one shared mount immediately before sampling). 20 of 32 nodes FAILed with
dstate=1 after a storm; 3 of 32 still did on a quiesced cluster; a manual
re-sample 25s later found ZERO. Corrected to sample twice and convict only a
task **still in D by PID** after a 10s dwell, reporting `pid:comm:wchan`.
Strictly MORE specific, not a lower bar — an unchanged-PID wedge trivially
survives 10s. **It found this defect on its first run.**

## RULE 5 note

GPT was consulted after two hypotheses were refuted. It independently ranked
cross-path claim corruption as the leading hypothesis and recommended exactly
the cookie/ring instrument that then proved it. Its standing structural
recommendation, NOT yet implemented: hand the potentially-final `xfs_irele` to
a worker holding no DLM state, after the release completes and state has left
DEMOTING, instead of having the release executor do it. Also `xfs_irele(ip)`
followed by touching `ip` is a lifetime hazard on its own.

## Residual

Two release drains still run concurrently on one inode (72/run). The fix makes
that survivable, not impossible.
