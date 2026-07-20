---
name: sess44-force-block-0-suite-sweep
description: sess44 full ./run.sh 2 tcp on force_block=0 build 9A10A077: coherency family ALL PASS in-suite; residuals = posix_multi(1chk), dlm_membership, rsync_…
metadata:
  type: project
---

## sess44 — full `./run.sh 2 tcp` suite, build 9A10A0773B7002BA33D2EAD (force_block=0 DEFAULT)

### Fix landed: `int mxfs_dir_force_block = 0;` (was 1) in xfs/xfs_mxfs_dlm.c:2789. Rebuilt
9A10A077. PROVEN that force_block=1 was the regression [[sess44-BREAKTHROUGH-force-block-1-is-the-regression]].

### FULL-SUITE in-suite results (ONE prep, NO reboot between — the real criterion), partial:
- PASS: precond_readiness, **cache_coherency 2/2 (90-session blocker, GREEN in-suite!)**,
  strong_consistency, mmap_coherency, zero_silent_loss, **dlm_fairness 2/2 (was FAIL)**,
  scaling_curve, dlm_scaling.
- FAIL: **posix_multi 1/2** (test2 ONE check: `pm r2 sees node1 renamed content exp=posix_1 got=`
  — empty-content read of a peer's renamed hardlink; sess39/45 empty-content family; test1
  PASS 211/211), **dlm_membership 1/2** (coord=fault), **rsync_paired 0/2** (both; 400-file
  rsync into own subdir, 90s window — timing-under-load or contamination from preceding fault test).
- (crash_consistency, dir_reuse_coherency, fence_during_write, fault_netpartition, soak,
  tcp_dlm_scaling still running at this note.)

### PATTERN: the pure cross-node COHERENCY tests now PASS in-suite. Residuals cluster on
(a) heavier/metadata workloads (rsync_paired), (b) fault tests (dlm_membership + the pending
fence/netpartition/crash), and (c) one transient empty-content read (posix_multi). Strong
hypothesis: dominant residual cause = CONTAMINATION/cumulative degradation (the suite never
re-preps; a fault test that doesn't cleanly recover degrades downstream tests) PLUS the
posix_multi empty-content coherency gap.

### DIRECTION (user: FIX ROOT, no workaround, no flag-flip-to-pass, no git, no restore):
1. Get the COMPLETE 17-test result (suite running bg task bbxhykdow).
2. Re-run each FAIL STANDALONE (`./run.sh 2 tcp <test>`, fresh prep, reboot if shutdown) to
   split REAL-bug vs CONTAMINATION. dlm_fairness/cache_coherency/dir_reuse already PASS standalone+in-suite.
3. For genuine contamination: the fix is the fault tests' clean node-rejoin recovery (NOT
   mkfs-between-tests — that would mask real wedge bugs; user forbids workarounds). A real
   clustered FS must survive back-to-back workloads.
4. posix_multi empty-content: same family as cache_coherency cross_write_read (now passing) —
   likely a hardlink+rename content-visibility path residual.
### METHOD REMINDERS: virsh destroy/start both nodes after ANY shutdown; `dmesg -C` before each
run; foreground runs auto-background past ~90s (await task-notification, don't poll).</body>
