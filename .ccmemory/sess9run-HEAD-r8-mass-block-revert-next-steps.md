---
name: sess9run-HEAD-r8-mass-block-revert-next-steps
description: sess9 HEAD: build 2493D345, 4/tcp = 17/17 twice (r5,r7), residual flake = mass single-block revert (r8 round13, 59 names). Repro loop running. Next s…
metadata:
  type: project
---

# sess9 HEAD — state at relay boundary

## Build 2493D345 (deployed, current) — fix stack this session
- FIX-26v3: bast_process release-abort when tenure gen moved mid-drain (entry-gen capture) + state=CACHED + i_dlm_bast_pending armed; ilock_end fires on `CACHED && bast_pending` (peer served promptly, not on 6s retry).
- FIX-27: ilock_begin EDEADLK retry recursion → `goto restart` bounded loop (64-lap cap → shutdown); fixed the test1 stack-overflow panic.
- FIX-25 widened: ioend admit under PR (test2 900s wedge fixed).
- FIX-28: deferred-publish skips master-EX claim when FS-layer EX gone (was ~1000 phantom ghosts/node/run).
- Ledgers: P9-LFREE (make_free, cap 60000 — EXHAUSTS mid-suite, only reliable standalone/fresh-boot), P13-LADD realns, P9-NLEDGE (s_remove_count skew).

## 4/tcp full-suite score history (clean cycle each)
r1 14/17 → r2 16/17 (soak destroy-WARN) → r3 15/17 (test2 wedge) → r4 16/17 (dlm_scaling 3/4) → **r5 17/17** → r6 16/17 (tds pace, fixed by v3) → **r7 17/17** → r8 16/17 (dir_reuse 0/4 round 13 mass revert).

## r8 residual failure — mass single-block revert (NEXT TARGET)
Round 13: 59 names LOOKUP_ENOENT on all 4 nodes: node1 f4–f50 ENTIRELY + node2 f9–f12 + node3 f11–f13 + node4 f10–f14; ALL .md5 names survived. Reading: ONE data block durably reverted to birth-era image — node1's adds concentrated there (per-node bestfree placement), peers only had their f9-f14-era adds in it, md5 phase went to later blocks. Class = daddr-reuse ABA / stale-lineage whole-block write (P13-STALEREAD / b_mxfs_dir_incarn guard family), NOT the fixed same-aoff race. t1 evidence lost (dmesg ring rotated + P9-LFREE cap exhausted).

## In flight at boundary
3× standalone repro loop RUNNING: `MXFS_EXTRA_MODARGS='dir_relverify=1 leafprobe=1' ./run.sh 4 tcp dir_reuse_coherency` — log at scratchpad/drc_loop_r9.log (session c928f1b6 scratchpad). On FAIL: fresh caps + full ledgers; replay the daddr like this session (P13-LADD/P3W/P9-LFREE by realns; survivors-by-rm-frees inversion). If 3× PASS: mass-revert needs suite context (cross-test residue) — reproduce via suite-prefix then dir_reuse.

## Remaining flake inventory for 4/tcp 100%-consistency
1. dir_reuse mass block revert (r8) — above.
2. dlm_scaling SF-dir setup race (r4 3/4: own mkdir dirent lost in concurrent SF mkdir; FIX-28 may have fixed — no recurrence since).
3. soak s_remove_count WARN flood (r2 only; P9-NLEDGE armed, unexplained; xfs_reinit_inode recycle-at-zero = proven +1 INFLATION site, underflow source unknown).
4. Watch: P73-WAITSTALL wedge recurrence (FIX-25-widened should cover the PR shape).

## Ladder after 4/tcp is consistent
8/tcp (boot test5-8 too) → 2/tcp → 1/tcp. Criteria = 17/17 at each of 1/2/4/8. Marker NOT written.
