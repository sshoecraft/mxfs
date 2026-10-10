---
name: compiled-gate-verdict-propagation-and-harness-measurement-vacuity-traps
description: Gates and probes that lie by omission: errno collapse, overwritten revisit state, silent instruments, one-name assertions, wrong acquire/reach reads.
metadata:
  type: feedback
tags: [compiled, traps, harness, measurement-integrity, gates, fallible-acquire]
---

# Gates, probes and harness assertions that report something other than what the code did

Seven traps with one shape: a gate, instrument or assertion names or reads one thing while the mechanism did another, and nothing warns. Code compiles, logs look healthy, a lap prints clean or FAIL. Grouped by where the lie enters.

## 1. A gate's answer is collapsed or destroyed

- **Truth-testing a verdict gate.** `mxfs_inode_incarn_estale()` answered only 0/-ESTALE until 0.74.0, then also -EIO (RECOVERY_BLOCKED covers the inode, quarantined victim domain). Twelve gates in `pal/linux/xfs_file.c` still did `if (gate(ip)) return -ESTALE;`, rewriting every -EIO into "Stale file handle". Lap s7a_realignB_l1 showed 13/40 and 17/40 reads ESTALE in 3-5 ms with zero poison probes; the ten P-RBLK-COVERS-DEAD-MASTER refusals named exactly the first ten ESTALE'd files. The iomap and fsync gates, written later, already propagated. Fixed in 0.90.14, verified by s8a_realignB_l1 (every read 0 or EIO).
  - A helper returning an errno is propagated (`rc = gate(ip); if (rc) return rc;`). Truth-test only where the caller cannot return an errno (fault handler), and say so at the site.
  - When a gate gains a verdict, grep every caller for `if (gate(` and fix them in the same change. Reading the gate shows what it returns; reading its callers shows what the user sees.
  - A fail-fast lap must assert the errno class (0 or EIO), not just "returned quickly".
- **Revisit gate keyed on volatile state the same function overwrites.** The fencing revisit gate read the in-core `CERT_UNRECORDED` reason, then the acquire path fell through to record generic `NO_CERTIFICATE` over it. `NO_CERTIFICATE` is implied by `CERT_UNRECORDED`, not an alternative to it; writing the implication over the cause destroyed the state. `tests/fence_cert_publish.sh <label> spent` (2/tcp): 6 `P238-FENCE-HOLDER-STATE` visits, 1 `P238-FENCE-RESUME`, 0 `RESUME-BOOTLIVE`, and the returning peer got MOUNT_RC=32. The second arm of the gate (`MAY_HAVE_RUN`) was never armed because the sole-survivor exclusive-write gate submits no command needing a durable pre-submission boundary, so the gate rested wholly on the in-core half.
  - A periodic revisit that "looks and does nothing": count visits and actions separately (6 visits / 1 action differs from 0 visits). Find every writer of the state the gate reads (grep the setter, not the enum). Ask whether the two values are alternatives or one implies the other.
  - Fix (0.89.14): a standing `CERT_UNRECORDED` for the same victim is kept when a generic `NO_CERTIFICATE` is recorded, refreshing only liveness fields. Stronger shape not yet done: carry "proved but unpublished" on the on-disk descriptor. A gate keyed on the in-memory accelerator alone is not crash-closed.

## 2. The instrument cannot distinguish "clean" from "never reached"

- A probe that logs only on the failing path makes "no failure" and "never reached" identical. `v5_tcp_release_gate()` printed `P-TCP-RELEASE-POISONED` only on refusal, so D-0945 was reasoned about for a session without an on-demand reproduction. Fix: fire on both arms of the knob (`P945-INO-FREE-RELEASE ino=N poisoned=1 gated=0|1`); it fired on 2 of 6 laps, so 4 would have been miscounted as correct. A lap that never took the route reports "not exercised".
- The choke-point census `P945-RELEASE-WHILE-POISONED` (0.75.115) returned zero over ten death laps. A dead probe (wrong `cb_data`, unregistered callback, branch not taken in this config) also returns zero. `tests/d0945_chokepoint_positive_control.sh` uses an existing 0644 knob (`poison_gate_ino_free=1` must be silent, `=0` must fire) so both arms have a defined right answer in one run.
- Before a zero count becomes evidence, prove the instrument can produce a non-zero one, in the same run. A negative can be false in the kernel, not only in a subagent's report.
- Related: `agmeta_shutdown_retire.sh` scored the injected death by grepping log-error text, so a shutdown via a different route scored "no shutdown" and buried D-0946 for a session; assert the unexpected route explicitly. Files `tests/evidence/<lap>/*.txt` are dmesg tails carrying earlier laps and boots (16 ATOMIC-SKIPs counted against a driver score of 0); they are not windowed to the lap.

## 3. The assertion names one of several identities

- The recovery-blocked refusal in `dlm/dlm.c` prints as `P240-RBLK-EIO-ABORT` (acquire path), `P-RBLK-COVERS-DEAD-MASTER` (entry gate, resource mastered by the blocked node) or `P-RBLK-COVERS-DEAD-HOLDER` (entry gate, merely held). Which fires depends on which node masters the inode and changes lap to lap. Lap s75b: two probes returned real EIO, the assertion `P240-RBLK-EIO-ABORT >= 1` read 0 and FAILed. Sum every name the mechanism can print and report the breakdown (`acquire-abort=0 entry-gate-dead-master=2 entry-gate-dead-holder=0`). An assertion citing one identity fails exactly when the mechanism took its other branch.

## 4. The harness arranges the wrong site (D-0958, fallible-acquire laps)

- **A shell cannot hold an O_DIRECT fd.** The black-hole arm (s596d, 0.84.13) parked `sh -c` with `exec 9< FILE` then a python doing `os.open(O_WRONLY|O_DIRECT)` after the fault was armed; the blocked stack was `xfs_file_open -> mxfs_dlm_open_protect` and the verdict `P912-OPEN-UNRECEIPTED` scored open, not the write. Park `tests/dio_unaligned_pwrite.py` (open O_DIRECT, opened marker, wait for go marker, one pwrite) exec'd in place of the shell so the recorded pid survives.
- **A direct write's first request is its timestamp update.** With a cached PR the shared IOLOCK ride fast-paths, then `xfs_file_write_checks -> kiocb_modified -> xfs_vn_update_time` takes `ILOCK_EXCL` (a cluster EX) in a clean `tr_fsyncts` reservation, before `iomap_dio_rw`. That EX is what a discarded request meets; until 0.84.14 it was non-fallible (waits forever, DEGRADED). Fix registers the inode around `kiocb_modified` and cancels the clean reservation on refusal (`P958-WRITE-REFUSED stage=timestamp`). The retry's own ride is reachable only when no timestamp update was needed (coarse mgtime tick unchanged), which cannot be arranged on demand; its conversion rests on the reference-iomap proof. Any "which acquire meets the fault" reasoning for a write must include the timestamp transaction. The live-holder control needs a clean PR on the holder beside the writer's cached PR (`live_holder_wait.sh HOLDER=pr`: re-dirty+sync, W reads, H reads, then arm the pause).
- **A cached PR is not a fast path when the inode is stale.** The cached-mode fast path in `mxfs_dlm_ilock_begin` serves PR from a cached PR only when `!ip->i_dlm_stale`, and `i_dlm_stale` is set by ~20 coherency signals; the reload clears it once per staleness event. s596g (0.84.14, held_fd_dio_unaligned) landed `P958-WRITE-REFUSED stage=first mode=shared` instead of the timestamp site. A cached EX serves anything. A lap reaching a LATER acquire cannot rely on a preceding read to make earlier rides fast; it must accept either stage and print which. Under the fallible model the FAILs were harness expectations, not MXFS defects.
- s596h `got=2 want=1` pause count: with HOLDER=pr the holder's EX-to-PR demote from W's re-cache read was still draining in the bast worker when the pause was armed; W's EX 0.5 s later paused a second drain. Arm-after-drain needs the demote completed, not the read returned.

## 5. Severity and reach are separate reads (D-queue scoping)

- `mxfs_iclus_lock` (`xfs/xfs_mxfs_dlm.c`) is an untimed `TASK_UNINTERRUPTIBLE` `wait_event` naming neither `xfs_is_shutdown` nor the authority: reading the wait grades the hazard, and proves nothing about which release it blocks. It is reachable only on CAW: `mxfs_iclus_routed()` requires `mxfs_v5_dlm_transport_caw()` and `icluster_dlm` is a load-time 0444 int, default 0. On TCP it never executes.
- Reach is graded by reading every call site's gate. Of five: two via `mxfs_dlm_iclus_covered()` (a twin returning `mxfs_iclus_routed(ip)`), one with an explicit `mxfs_icluster_dlm && transport_caw` test, one with no local transport gate, protected only by sitting inside `if (pub_routed)` 96 lines up (needed all four references to `pub_routed` enumerated). One ungated caller would reopen the question.
- Scoping is not a disposition: the site stays an open unkillable-hang hazard for any CAW release. Its fix needs a terminal term in the condition and a waker on the closure path; the only all-cluster sweep runs from `put_super` and `kfree`s without waking waiters.
- A brace-depth scan for `for(;;)`/`while(1)` around a sleep gave 16 "unbounded-shaped" loops in `dlm/`; all 16 terminate. A shape scan locates candidates; only reading each dispositions it.

## Checklist distilled

1. Propagate gate verdicts; grep callers when a gate gains an answer.
2. Never overwrite a specific cause with its implication.
3. Prove an instrument can fire (positive control, both knob arms) before reading its zero.
4. Assert on the sum of every printed identity of a mechanism and print the breakdown.
5. Verify the harness reaches the intended acquire site (fd type, timestamp EX, stale flag, drain ordering) from the blocked stack, not from the arming order.
6. Grade reach per call site, and keep scoped-out hazards in the queue.

Sources: [[trap-truth-testing-a-gate-that-returns-a-verdict-rewrites-every-verdict-into-one-errno]], [[trap-a-cached-pr-is-not-a-fast-path-when-the-inode-is-marked-stale-so-a-writes-first-request-moves]], [[trap-a-direct-write-with-a-cached-pr-sends-its-timestamp-ex-first-and-a-shell-park-cannot-open-o-direct]], [[trap-a-revisit-gate-keyed-on-volatile-state-that-the-same-function-overwrites-fires-exactly-once]], [[trap-a-silent-instrument-and-a-clean-system-are-the-same-observation]], [[trap-a-refusal-with-three-log-names-fails-a-lap-when-the-assertion-cites-only-one]], [[trap-a-hang-site-can-be-gated-out-of-a-release-by-its-transport-and-only-every-call-sites-gate-says-so]].
