---
name: sess382-fenced-publication-fix-landed-0182-and-its-residual
description: sess382: fenced-publication wedge fix landed 0.18.2, verified by paired A/B on one build via new fault injection; STILL OPEN — natural-case adopt bai…
metadata:
  type: project
tags: [mxfs, wedge, obligation, iflush, fault-injection, rule6]
---

# sess382 — the fenced-publication wedge: fix, verification, and the gap

Final build **0.18.2 sv `89F66602EBFA099CE4E9281`**. Defect
`D-RELOG-BEHIND-DISK-OBLIGATION-DEADLOCK-WEDGE-380` **remains OPEN**.

## The fix (three changes)

**(A) One chokepoint for "this flush was abandoned."** `xfs_iflush`'s `flush_out`
sets a new `i_mxfs_pub_fenced` when it returns SUCCESS having not stamped
`i_mxfs_pub_flush_seq` while `pending != durable`. Checked in ONE place instead
of at each of the eleven fences, and it covers any fence added later.

**(B) A release-side consumer.** `mxfs_dlm_bast_dwork_fn` (the retry worker —
outside the drain, so not the ABBA folio-lock site) drives
`mxfs_dlm_reload_inode` for a fenced publication *before* the deadline check
that would wedge. It never touches `durable_seq` and invents no verdict: the
existing keep-guards stay the sole authority, and a dropped change is still
reported by `P177-OBLIGATION-DROPPED-AT-ADOPT`. Bounded at
`MXFS_RELDEFER_RELOAD_MAX=3`; a bailed adopt does **not** restamp progress, so
fail-closed is preserved. Probe `P382-RELDEFER-RELOAD`, lever
`mxfs.reldefer_reload`.

**(C) The counter runaway.** `xfs_trans_log_inode` no longer bumps `pending_seq`
under `i_mxfs_pipe_relog` — the drain's own re-log is not a new committed change,
and counting it made the obligation permanently uncloseable.

**A bug in my own fix**, caught by reading the init path: `xfs_inode_alloc` uses
`kmem_cache_alloc`, **not** zalloc, so both new fields had to join the explicit
reset block or a recycled inode inherits a previous incarnation's verdict.

## The technique that made this provable: give the cause a switch

Every natural trigger is luck-dependent. `mxfs.iflush_fence_fault_ino` makes a
chosen inode's flush take exactly the fence shape (error=0, no `flush_seq` stamp,
`i_dlm_stale` set). `tests/iflush_fence_wedge.sh` drives it in ~90 s.

Pre-fix 0.17.6: `P-IFLUSH-FENCE-FAULT`=721, pending **6→730** with flush frozen at
6, `P-INODE-WEDGE` `tries=714 causes=0x1`, MOUNT=DOWN — the *identical* signature
to test31's natural occurrence, so the injection reproduces the real chain.

Paired A/B, ONE build (0.18.0), lever flipped at runtime, same fault:

| lever | hits | durable | P146V | P228 | WEDGE | MOUNT |
|---|---|---|---|---|---|---|
| 1 | 4 | 6→**10** | 2 | 1 | **0** | **UP** |
| 0 | 689 | stuck **6** | 122 | 401 | **1** | **DOWN** |

Repeated on 0.18.1 and 0.18.2. Full 32/caw board **25 PASS / 2 FLAKY / 0 FAIL /
1 policy cell** on all three builds. Natural engagement fell 199 → 9 firings when
the trigger was tightened from `i_dlm_stale` to the chokepoint, while
`P228-RELBAR-DEFER` went 19→0 and `P176-OBLIGATION-OPEN` 17→0.

## WHY IT IS STILL OPEN — do not let a later session forget this

All **nine** natural `P382-RELDEFER-RELOAD` firings read `closed=0`: the adopt
**bailed** on its keep-guards and the obligation was not reconciled
(`pend=18->18 dur=16->16`). So the fix is proven against the *injected* cause
(where the inode is healthy and the adopt succeeds) but its efficacy on the
*natural* trigger is **unproven**. Nothing wedged in those nine — but nothing
needed to (`P228`=0, no release was even deferred).

If a natural fence were permanent and the adopt bailed, this fix would add three
reload attempts and then wedge anyway. Closing on the injected arm alone is
exactly the "clean run / plausible explanation" disposition RULE 6 forbids.

**Next:** instrument `mxfs_dlm_reload_inode`'s bail points with a reason code and
surface it in `P382-RELDEFER-RELOAD`. **P34J demote-wait is the prime suspect** —
the reload runs while a demote is active. If so, sequence the reload against the
demote (the ruling's drain → resolve → release order). Closure needs a
natural-fence sweep showing `closed=1`.

## Method notes worth reusing

- **Give the cause a switch.** Three attempts to force the wedge with existing
  knobs gave one hit; a 20-line fault injection gave it every time. When a defect
  is luck-dependent, building the switch is cheaper than waiting.
- **A no-op patch looks like a fix.** The P32E contract hole was real and I fixed
  it, but `RAWDIVERGE=0` over 14 firings proved it changed nothing. Without that
  probe I would have credited it with the board going green.
- **Check `kmem_cache_alloc` vs zalloc before adding a field to `xfs_inode`.**
