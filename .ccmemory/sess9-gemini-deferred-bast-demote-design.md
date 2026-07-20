---
name: sess9-gemini-deferred-bast-demote-design
description: sess9 Gemini RULE-5 design for the cached-EX stale-RMW residual: strict DLM demote state machine — fast-path BLOCKS on i_dlm_stale (not reload), hono…
metadata:
  type: project
---

## Gemini design (gemini-pro-latest, RULE-5 justified: complete diagnosis + 3 refuted fixes + design-level Q). For the ~1/30 cached-EX-outlives-grant stale-RMW residual on build 427DB5AF. See [[sess9-three-refuted-fixes-for-cached-ex-residual]].

## Core verdict
A/B/C all tried to solve a LOCK-STATE problem with DATA-layer checks (reload / di_lsn compare) — wrong. The bug: the dir EX FAST PATH leaks operations while a BAST revocation is pending (i_dlm_stale set but lock still cached EX). Fix the DLM state machine; then coherency is by mutual exclusion with ZERO extra disk reads on the fast path.

## The pattern (implement this; matches GFS2 glock / OCFS2 / VMS)
1. **Fast-path BARRIER (the missing piece):** dir EX fast path must consult i_dlm_stale, but DO NOT reload (that's approach A's starvation). Instead BLOCK: `if (unlikely(ip->i_dlm_stale)) wait_event(ip->i_dlm_wait, !ip->i_dlm_stale);` then re-evaluate (lock no longer held → slow-path re-acquire). ~zero cost on the uncontended/self-created path.
2. **Honor point (last ilock_end / unpin):** if i_dlm_stale set → SYNCHRONOUS flush committed metadata to the coherent LUN → DLM demote (give up EX) → invalidate/purge in-core shortform fork → clear i_dlm_stale → wake_up_all(i_dlm_wait). (The sess9 cluster-flush fix already does the synchronous-flush-before-release half.)
3. **Minimum Hold Time (CRUCIAL anti-starvation — why approach A failed):** stamp i_dlm_ex_acquire_ns at EX grant (ALREADY stamped, xfs_mxfs_dlm.c ~7037/7156). On BAST arrival, if `time_before(jiffies, grant+MIN_HOLD)` (~5-10ms), DEFER setting i_dlm_stale via a delayed workqueue so the node batches ~5-10 local fast-path ops before the barrier drops. Without this, 2 nodes hammering one dir ping-pong the lock per-op → the got=7/8 starvation I measured.
4. **DROP di_lsn vs li_lsn (approach C) and the disk-compare reload (P9 helper) for this purpose.** With strict mutual exclusion + flush-before-demote: holder = in-core is ground truth (never read disk); acquirer = read disk EXACTLY ONCE on grant, then trust in-core until next lose+re-acquire. The destage race vanishes (previous owner flushed synchronously before acking the demote).

## Implementation notes / sites
- BAST deferral today: bast_notify (xfs_mxfs_dlm.c ~4540 ACQUIRING branch sets i_dlm_stale; ~4628-4649 P-NONE-HELD-DEFER/RELEASE). Honor at ilock_end. VERIFY the deferred BAST actually reaches a demote at ilock_end/unpin (instrument: does P-NONE-HELD-DEFER always get a matching demote?). 
- Add the wait_event barrier in mxfs_dlm_ilock_begin's dir EX fast-path (the holder-increment `else` block ~6447) BEFORE incrementing holders, gated S_ISDIR && mode==EX && !single_node (and skip i_dlm_demoter==current to avoid self-deadlock).
- MIN_HOLD: in the BAST path, schedule delayed honor instead of immediate i_dlm_stale when within the window.
- Keep the sess9 KEEP fixes (remove/rename cluster durable; EAGAIN-IN_AIL submit). The P9 disk-compare helper can be REMOVED once the barrier works (it was a data-layer patch for the same hole).
- Validate: dlm_fairness 30x (watch for both resurrection AND got<50 starvation), full suite 3x reboot-between = 16/16, rsync wall RULE-0.
