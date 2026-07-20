---
name: sess16run-PIVOTAL-P106-overlapping-EX-grants-and-timing-race
description: sess16(ccloop) PIVOTAL: (1) dir_reuse loss is a TIMING RACE not deterministic — same dirwr=2 config PASSED 8/8 (heavy tracing masks it). (2) P106-EXG…
metadata:
  type: project
---

## sess16 (ccloop) — PIVOTAL correction + the double-grant lead

### Correction 1: the loss is a TIMING RACE, not deterministic
A run with `inode_mht_ms=50 dirwr=2 MXFS_TEST_ENV='DRC_ROUNDS=2'` **PASSED 8/8** — the SAME config that failed in two earlier runs this session. The heavy dirwr=2 per-IO content tracing (P-DIRRD/P-DIRWR) adds enough IO latency to serialize the handoffs and CLOSE the race window (classic instr-masks-races, sess38/39). So [[sess16run-release-invalidate-REFUTED-points-to-DLM-grant-drain-ordering]] / [[sess16run-RESOLVED-f1-written-then-clobbered-on-hot-block0]] "deterministic node1_f1/node5_f40" was an artifact of consistent NON-traced failures; the loss is timing/frequency-sensitive (consistent with EX-handoff-mid-RMW). IMPLICATION: never trust a dirwr=2/instr=1 PASS — always validate a fix at dirwr=0/instr=0.

### Correction 2 (THE LEAD): pervasive OVERLAPPING EX grants on ino=131
P106-EXGRANT (acquire) / P106-EXREL (release) — the detector PURPOSE-BUILT (sess106, xfs_mxfs_dlm.c:11769) to answer "do two nodes hold the SAME dir inode EX OVERLAPPING (mutual-exclusion / double-grant failure) vs serialized?" — fired 420× for ino=131. A naive single-holder pairing (grant sets holder, same-node rel clears) shows DOZENS of overlaps even on the PASS run: "test3 grants while test2 holds", "test4 grants while test1 holds", "test2 grants while test4 holds", etc. Two nodes apparently hold EX on the shared dir simultaneously, pervasively.

### CAVEATS before trusting it (next session MUST resolve)
1. **Cross-node clock sync**: realns = each node's ktime_get_real_ns(); VMs may not be µs-synced. Verify (chrony/ptp offset) before comparing cross-node timestamps. The overlaps span large gaps so gross overlap is likely real, but confirm.
2. **Unpaired EXREL**: P106-EXREL may not fire on EVERY release (cap, or the PR→EX-upgrade / EDEADLK-recovery release path may not hit the EXREL site) → holder never cleared → FALSE overlap. Rigorously pair per-node grant→rel and count only true temporal overlaps where node A's [grant,rel] interval intersects node B's.
3. Overlap occurred on a PASS run → either overlap is an artifact, OR overlap alone isn't sufficient (the lost-update needs overlap AT the same block RMW). On a FAIL run the overlap may be tighter.

### NEXT SESSION — decisive
Run dirwr=2 capturing P106 + P-DIRWR until a FAIL occurs (or use a lighter probe that doesn't mask: a dedicated always-on P106 at instr=0). Rigorously pair grants/rels per node, verify clock sync, and check: at the moment of a daddr=120 count regression (the clobber), do the two writing nodes' EX tenures TRULY overlap? If YES → the bug is broken DLM mutual exclusion (dlm/dlm.c grant path — two EX granted, or grant-issued-before-prior-release-completes). Fix in dlm/: ensure the master never grants EX while another node's EX (or its in-flight bast_process drain) is outstanding; the direct PR→EX upgrade / REAFFIRM paths (dlm.c:512-527) are the prime suspects for issuing an EX that races the prior holder. If NO overlap at the clobber → back to the cross-tenure stale-base buffer ([[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]]).

### Build 42178C17 (new logic gated off at default). Criterion NOT met — marker not written. ALL of: force_coherent, postread_reread, b_mxfs_dir_epoch, dir_release_fua_write, dir_release_invalidate REFUTED at mht=50 (dirwr=0).</body>
