---
name: ccloop-c7ee71c6-sess206-P95-NL-setter-hunt-exits-audited-instr-design
description: sess206: #18 P95 fired ONCE fleet-wide; ilock_begin NL-exits audited+ruled out (admit_ioend, conv-fail-drop, bounded-tries); instr design ready (last…
metadata:
  type: project
---

# sess206 — #18 P95-OPEN-PROTECT-FAIL NL-setter hunt

## Established
- Fleet sweep of /tmp/run_rsync_paired_20260810T135045Z: exactly ONE
  P95-OPEN-PROTECT-FAIL across all 32 kernlogs (test19 13:52:49,
  ino=56623363). Single-shot race, not systemic.
- Audited every mxfs_dlm_ilock_begin exit path that could return with
  i_dlm_mode==NL for the rsync open path:
  - mxfs_ilock_admit_ioend (28422/28572): requires xfs_task_in_ioend()
    or in_writepages() — rsync open is neither. RULED OUT.
  - Bounded-tries timeout exit (29030): requires i_dlm_tries_owner ==
    current (xfs_lock_two_inodes). RULED OUT.
  - rc!=0 unrecoverable (29048): force-shutdown — FS stayed up. RULED OUT.
  - EDEADLK path (28917): restarts, never exits with NL (livelock cap
    → shutdown). RULED OUT.
- mxfs_dlm_inode_lock_routed (26703): the conv_pi drop of the old
  local grant happens ONLY inside rc==0 (26771). So open_protect's
  CLUSTER-CONVERT (36855) failing CANNOT leave NL. Sess205 hypothesis
  (a) drop-then-fail variant REFUTED by code.
- ALL 26 real i_dlm_mode assignment sites are in xfs_mxfs_dlm.c and
  every one transits mxfs_dlmtr_rec(om, os, __LINE__) (sess98 audit at
  line 1213 + fresh grep). Ring itself is watch_ino-gated → useless
  for unpredictable ino, but the rec function is the perfect chokepoint.

## Live hypothesis (open, uninstrumented)
Handoff hypothesis (b): ilock_begin fast-path served a cached mode +
registered pr_holder, then an in-flight iclus release sweep / bast
path set mode=NL before open_protect's re-read at 36861-63. OR an
unmapped setter. The stamped line number will decide — no more code
guessing (RULE 4).

## Instrumentation design (build as 0.11.473)
1. xfs_inode.h: u32 i_dlm_nl_line; pid_t i_dlm_nl_pid; u64 i_dlm_nl_ns;
   char i_dlm_nl_comm[16]; u8 i_dlm_nl_om.
2. mxfs_dlmtr_rec (1236), BEFORE watch gate: if (mode now NL && om!=NL)
   stamp fields. Unconditional, cheap, covers all 26 sites.
3. P95 arm: snapshot under i_dlm_lock at the 36861 read (print is after
   xfs_iunlock — do NOT read fields at print time): mode, state, ex/pr
   holders, acq_inflight, routed_iclus, unpublished, stale+src, i_mode
   octal, i_generation, open_n, self_created, reused_create,
   nl_line/nl_pid/nl_comm/nl_age_us.
4. make clean (multi-file .h change) + modules, deploy, loop
   rsync_paired until refire. Then RULE-5 consult on fix shape
   (retry-acquire vs -ESTALE vs -EIO).
