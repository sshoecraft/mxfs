---
name: sess52-orphan-runtests-contaminates-cluster-phase
description: sess52: cluster-phase barrier timeouts were caused by ORPHANED run_tests.sh from prior sessions, not an MXFS regression. How to kill them.
metadata:
  type: project
---

## sess52 (ccloop 14d31183) — orphaned run_tests.sh poisons every subsequent cluster-phase run

### Symptom
A clean `posix_phase_timing.sh --phase cluster` run had tests that PASSED in sess51
(cross_write_read 9s, dir_stress) suddenly FAIL with **246s = 2×120s barrier timeouts**,
cluster-wide. Looked like a coherency regression. It was NOT — same build 5D6E7445.

### Root cause (PROVEN via `ps -eo pid,etime,cmd`)
Prior sessions' phase runs were **still alive as orphans**: sess51's
`tests/criteria/posix_phase_timing.sh` (pid age 2h18m) + its child
`tests/run_tests.sh --phase cluster`, plus a swarm of `mxfs_test.sh` /
`mxfs_sshpass.sh root@testN` ssh fan-out stuck 46+ min in `barrier_wait`.
These orphans keep touching barrier files in the shared `.mxfs_barriers/*` dirs
and contending for inode locks → the *current* run's barriers never converge → 120s
timeout on every barrier. sess51's run got stuck at `test_rename_vis_dbg` and was
never reaped (ccloop relay boundary), holding the cluster hostage.

### Why it's sticky (two traps)
1. **Killing the posix_phase_timing PARENT does NOT kill run_tests.sh** — the child
   reparents to init (pid 1) and keeps looping to the NEXT test, re-spawning ssh.
2. **It survives a power-cycle** — `cluster_reset_n.sh` reboots the VMs (kills in-guest
   mxfs_test), but the host-side run_tests just reconnects to the rebooted nodes for
   its next test. `pkill -9 -f run_tests.sh` can MISS it if it's D-state on the wedged FS.

### Reliable cleanup recipe (do this BEFORE every measured cluster run)
```
# 1. find every orchestrator
ps -eo pid,etime,cmd | grep -iE "posix_phase|run_tests\.sh|mxfs_test\.sh|ssh .*root@test" | grep -v grep
# 2. kill run_tests.sh BY PID with -9 (not just pkill -f; not just the parent)
kill -9 <each run_tests pid> <each posix_phase pid>
# 3. mop up children
pkill -9 -f mxfs_test.sh; pkill -9 -f "mxfs_sshpass.sh test"; for h in $(seq 1 16); do pkill -9 -f "root@test${h}.vm"; done
# 4. VERIFY zero: ps ... | wc -l  → must be 0 before launching
# 5. THEN cluster_reset_n.sh 16 for clean in-guest state
```
**Launch future phase runs with `setsid`/tracked PID so the whole process group can be
killed as a unit; NEVER leave a phase run orphaned at a relay boundary.** If a run must
be abandoned, kill its run_tests pid first.

### Knock-on: SCST PR wedge
The orphan swarm's stuck mid-I/O + my virsh churn re-triggered the SCST CAW↔READ atomic
wedge (register-ignore ACKs but key never sticks → mkfs EBADE "Invalid exchange").
Recovered per [[sess47-scst-wedge-pr-recovery-procedure]]: gdb /proc/kcore edges →
scst_unwedge.ko blocker=<READ 0x28> blocked=<CAW 0x89> → preempt-abort+clear PR. 18
D-state iscsi_conn_cleanup → 0 after one edge break.

### Bottom line for the criterion
posix_semantics_multi16 must be measured on a VERIFIED-orphan-free + power-cycled cluster.
sess51's per-test PASS numbers (cross_write_read 9s etc.) are the real baseline; the
"regression" was contamination.
