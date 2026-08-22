---
name: ccloop-c7ee71c6-sess316-zsl-stale-inode-regression-512-knobon
description: sess316: 0.11.512 knob-on REGRESSION — zsl FAIL 2/2: test1 serves stale ino=136 (size=14, stale bmap reads .md5 blocks) across re-acquire; UNLEDGERED
metadata:
  type: project
---

# sess316 — zsl silent-loss regression on 0.11.512 knob-on (REPRODUCED, root OPEN)

## Facts
- Deployed 0.11.512 (sv DF5630A9C55F783FB6B8E56) knob-on
  (icluster_dlm=1, release_proof_enforce=1) 32/caw, prep 226s.
- zero_silent_loss FAIL 2/2 (2026-08-15 07:59Z + 08:04Z), identical:
  test1 ONLY, node7_data1 (ino=136) md5+size fail — size 14 vs 262144.
- Live post-test forensics: test1 `stat` = ino136 size=14 mtime OLD
  (~460s older than fleet); first 14 bytes = the CURRENT run's expected
  md5 hex prefix, i.e. test1's stale bmap points at disk blocks now
  allocated to node7_data1.md5's data. test7/test2 = 262144, correct
  content, same ino 136. => test1 kept a STALE INODE INCARNATION
  (size+bmap) across DLM grant re-acquisition — reload never ran.
- test1 dmesg: P79-STALEBAST-CLEAR ino=136 ×2 (sess4-era path,
  pre-existing) and P79-NESTADMIT ino=132 comm=md5sum. NO P228/episode
  probes on test1 → sess315 episode legs likely not directly involved.
- .511 passed zsl repeatedly earlier the same day (criteria history) →
  regression window = the sess315 INODE-containment surgery ONLY
  (ilock_begin divert gate ~28650, wait-loop predicates 30007-30059,
  postwait re-admit 30153, in-loop arms 30175+).
- Board context: cache_coherency FAILed its first post-prep run
  60s/60s NO_TERMINAL_RECORD×32 then PASSed 42s (marginal-pace
  family); dlm_fairness FAIL 30/30 NO_TERMINAL_RECORD×32 (unretried).
  rsync_paired 57/60s close. Possible fleet-wide pace tax from the new
  per-admission checks — unmeasured.

## RULE 4 state
Hypothesis OPEN (uninstrumented): a sess315 ilock_begin edit admits a
re-acquire without the mxfs_dlm_reload_inode / FUA-fresh chokepoint.
Next: forensics on test1's LIVE stale state (do NOT re-prep first),
then trace the .511→.512 admit-flow diff for the
STALEBAST-CLEAR→slow-path→reload sequence.

## Also this session
- tests/relgate_fault_inject.sh gained inode + inodewedge modes
  (force-based INODE legs, class=1 certs, pin_rc/defer=5 asserts);
  bash -n clean, NOT yet run. INODE legs need icluster_dlm=0.
- make tools done for 0.11.512.
- NEW defect is UNLEDGERED — add to OPEN_DEFECTS.json (critical).
