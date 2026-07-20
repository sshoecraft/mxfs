---
name: sess15run-FIXH3-final-shape-and-validation-ladder
description: sess15 FIX-H3 (3C674F70): orphan_live abort + strikes + self-demote exemption. r14 8/tcp 17/17. H2 lesson: blocking EDEADLK self-demote = cluster wed…
metadata:
  type: project
---

# FIX-H iteration history (sess15) — final shape = FIX-H3, build 3C674F70

## The three builds
1. **FIX-H (CBD34F20)**: orphan_live abort (p_held_mode==NL && p_rel_gen!=0)
   at the P15 recheck + P135-GRANTWIN-PARK queue-time gate (held==1 && gg!=0
   → park BAST to dwork instead of queueing orphan release).
   r11 = 16/17 (drc+tds PASS — the r10 double-EX face FIXED; fence 7/8 new).
2. **FIX-H2 (7C321E23)**: + strike escalation (4 same-gen samples → stranded
   release), state=NONE for pure-orphan aborts, 25ms dwork re-arm
   (bastq_src=14). r12 = 14/17: drc PASS again, but netpartition/tds died —
   ino 6291632 wedged 184s×2 (LKTIMEOUT rc=-110 shutdown cascade).
   r13 = 12/17 WORSE: ino 158/159 (infra dirs) wedged cluster-wide.
3. **FIX-H3 (3C674F70)**: + `!p_self_demote` exemption in orphan_live.
   **r14 = 17/17.**

## The r13 lesson (do not re-learn)
The P109 EDEADLK self-demote (xfs_mxfs_dlm.c ~18181, bastq_src=6, sets
i_dlm_self_demote before queueing) is THE resolver for a grant our own retry
loop stranded: it enters bast_process with in-core NL + live mirror gen —
the exact orphan_live signature.  Blocking it: acquirer rc=-35 loops (test2:
1009×), each master re-grant is a FRESH gen so strikes reset to 1 forever,
P15H-STRANDED-RELEASE fired only 11× — cluster LKTIMEOUT cascade.  The r10
double-EX killer (P135-queued, selfdem=0) remains blocked by the abort.

## Open faces at r14
- fence_during_write "own data intact": r11 node7, r12 node4 f23
  (exp!=got md5 on the node's OWN reg file; drop_caches re-read healed=0 →
  DURABLY stale; got-file size exactly 4096). r14 PASSED — probabilistic.
  Forensics now in tests/suite/fence_during_write.sh (FDW-MISS + kmsg marker
  + drop_caches re-read discriminator). NOT yet diagnosed.
- fdw hot-dir "shared hot dir drained" leak face: not seen this session.

## Validation ladder state (criteria: 1/2/4/8 tcp 100%)
- 8/tcp on FIX-H lineage: r11 16/17, r12 14/17(H2 wedge), r13 12/17(H2
  wedge), r14 17/17 (H3). Need repeats on H3 + all other columns.
- Next: r15 8/tcp, then 4/tcp, 2/tcp, 1/tcp on 3C674F70.
