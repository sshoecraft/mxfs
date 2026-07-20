---
name: sess-tcp-MILESTONE-full-suite-8pass-0fail
description: MILESTONE (build F22321): full 2/tcp suite = 8 PASS / 0 FAIL / 8 PENDING. cache_coherency+posix_multi+mmap+dlm_fairness all fixed by the -ETIMEDOUT l…
metadata:
  type: project
---

## MILESTONE — `./run.sh 2 tcp` = 8 PASS, 0 FAIL, 0 SKIP, 8 PENDING (build F22321508E13160ACFD9A41)
The -ETIMEDOUT lost-grant retry fix ([[sess-tcp-FIX-etimedout-retry-posix-multi-PASS]]) fixed
the ENTIRE 2-node coherency family in ONE shot:
- precond_readiness PASS, cache_coherency PASS 2/2 (the 90-session ship blocker!),
  strong_consistency 2/2, posix_multi 2/2, mmap_coherency 2/2, zero_silent_loss 2/2,
  dlm_fairness 2/2, soak PASS (30s, 1643 ops, 0 errs).
- 0 FAIL. (showstat 2 tcp)

## The 8 PENDING are NO-SCRIPT STUBS (not failures) — needed for an unambiguous "100%"
dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency,
fence_during_write, fault_netpartition (suite/), tcp_dlm_scaling (tcp/). No script exists in
tests/suite|tcp -> run.sh prints PEND, records nothing. criteria.json matrix for 2/tcp has
exactly 16 entries; 8 ran (PASS), 8 are stubs. The single-node P1 tests (posix_single, fsx,
fio_verify, integrity_filetypes, fio_perf, fault_enospc) are NOT in criteria.json's 2/tcp
matrix, so run.sh does not run them under this command.

## CRITERION INTERPRETATION (for the ccloop marker)
"2 node dlm=tcp test 100% successful". Runnable tests: 8/8 PASS, 0 FAIL = the substantive
goal (coherency suite green) is met. BUT 8 matrix entries are PENDING (unimplemented), so it
is NOT 100% of the declared matrix. Did NOT write the marker yet: (1) confirming reliability
with a re-run (prior state was FLAKY), and (2) PENDING tests should be ported+passing for an
honest 100%. Next session: port the PENDING tests (sources: tcp_dlm_scaling<-tests/cluster/
test_tcp_mesh.sh; dlm_membership/crash/fence/netpartition need fault-injection — model on the
coord 'fault' class + virsh destroy for node kill; scaling_curve/dlm_scaling/rsync_paired are
scale/perf — may be trivial/near-noop at N=2). Then re-run ./run.sh 2 tcp and confirm 16/16.

## KEEP fixes this session (all in F22321):
1. dlm: MXFS_LOCK_ACQUIRE_WAIT_MS=6000 (mxfs_dlm.h) + both dlm_lock_impl pending_wait sites
   + -ETIMEDOUT in mxfs_dlm_lock retry set = THE fix (lost dir-EX grant recovered in ~6s not 60s).
2. xfs_mxfs_dlm.c: bounded ifree drain (ifree_drain_ms=200) + mxfs_ail_drain_inode_sync_bounded.
3. xfs_mxfs_dlm.c bast_notify NONE_mode_held idle-release + P-DIRBAST diagnostic.
Build on test1+test2. Tooling in tests/: repro_burst_timed.sh, catch_create_stall.sh, etc.

## FOLLOW-UP (RULE 0): ~1 grant msg lost PER burst (systematic). Retry masks it in 6s.
Real fix = reliable grant/release delivery (master re-drive watchdog OR seq/ack/resend in
send_grant + LOCK_GRANT/LOCK_RELEASE recv). Optional: lower MXFS_LOCK_ACQUIRE_WAIT_MS to ~2s.
</body>
