---
name: AAA-ccloop7251-sess10-FRONT-A-CLOSED-drc32-first-green
description: drc@32/tcp FIRST GREEN ×2 (102s/107s, 58/58). 4 fixes: batch_arm grace-clamp, TCP abandoned-grant escape, reload_size_keep, run_bounded 100ms. Build…
metadata:
  type: project
tags: [ccloop-72513a13, sess10, front-a, drc, fixed]
---

# Front A closed — drc@32/tcp PASS ×2 (102s/107s, 58/58 checks, build 0650D30A = 0.11.38)

## Fix chain that got there (each RULE-4 proven before landing)
1. **batch_arm grace-slice clamp** (xfs_mxfs_dlm.c ~23052): the ACQUIRING-
   deferred BAST honor site armed the dwork for the FULL remaining mht window
   (300ms); every round-open first-claim slept it out (P70-BP held_ms=301-307).
   Clamp to dir_ex_batch_grace_ms slice like the src=9 site — create phase
   went 10s → 1.3-2s; handoffs 0.7-2ms (gen +246 in 170ms observed).
2. **Faster handoffs exposed 2 latent classes** (both intermittent, both fixed):
   a. **Unanimous-48 dirent clobber** (r1, ALL 32 nodes readdir=48/128): a
      write-side stale-base RMW made durable. Caught via P-CCREGRESS tripwire
      (xfs_inode_buf.c, di_changecount regression at destage, cap 300 —
      cross-incarnation reuse prints are noise; keep gen-qualified reads).
      Did not re-fire after fix 2b; watch on regression runs.
   b. **TCP abandoned-mirror-grant convoy** (the 125-128s cluster-wide verify
      stalls): a granted-but-never-consumed mirror grant (gen never P74'd,
      requester gone — retry dup-grant) wedged: P15-REL-ABORT(orph=1) ×5993/
      126s; ALL escapes defeated (starving reader's own ACQUIRING reset the
      280-strike counter + wall clocks every ~1s; P15H fired 0×); master
      starved 8 PR waiters (P-LKTIMEOUT-HOLDER held_ms=126854). FIXES:
      (i) removed the ageless TCP gg!=0 GRANTWIN-PARK (ACQWIN-PARK's
      acq_inflight>0 covers real mid-completion on both transports);
      (ii) P15-TCP-ORPH-PROCEED: orphan_live && acq_inflight==0 && gen
      unmoved && no holders, persistent >= tcp_orphan_force_ms (500, 0644
      param) on i_dlm_orphan_since_ns (reset ONLY on mode!=NL, never on
      ACQUIRING) → proceed to entry-anchored (gen-guarded) release.
3. **run_bounded 100ms polling** (tests/suite/lib.sh): the 1s kill-0/sleep
   lap quantized rm-rf (constant 4.02s while isolated rm=1.1-1.65s) and mkdir
   ~1s each per round in pure sleep. Threshold semantics unchanged.

## Round anatomy at green (rank1): create 1-2s (slowest node up to 5.1s —
## rotation-position), true verify 2.2-2.7s, rm ~1.6-3.3s (spread across 32
## creator AGs costs +0.6s; round context ~+1s more), coord ~1s. ~12s/round.

## rm micro-baselines on this rig (test1, 128 files): local-create 0.96s;
## 4-creator 1.12s; 31-peer-PR 1.04s; 20KB files 0.87s; 32-creator spread 1.65s.

## Front B regression: clean through all these runs (reload_size_keep=1 default
## in code). P-RELOAD-SIZESEVER/P-WU-CLAMP probes live (severs averted, content
## 43-58/58 green in every run since).
