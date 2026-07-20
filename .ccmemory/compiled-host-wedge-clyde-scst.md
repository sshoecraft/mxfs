---
name: compiled-host-wedge-clyde-scst
description: Compiled: recurring clyde SCST/iscsi_conn_cleanup D-state host wedge — reboot-only clear (user's call, RULE 2), trigger, and cluster-independent work.
metadata:
  type: project
tags: [compiled, host-wedge, clyde, scst, iscsi, rule2, recovery]
---

## Clyde host wedge — SCST/iscsi_conn_cleanup D-state livelock (reboot-only, user's call)

The MXFS dev host **clyde** periodically wedges hard on the SCST iSCSI target stack. Leaked
**D-state `iscsi_conn_cleanup` kernel threads** pin per-device command counts so every
strictly-serialized SCSI command (CAW, WRITE SAME) blocks forever in `EXEC_CHECK_BLOCKING`;
`scst.service` hangs "deactivating". **Only a host reboot clears the kernel-thread state**, and
per RULE 2 no session may reboot/sysrq clyde — the reboot is the USER'S call. This is not a new
bug: it is the known **sess14** wedge (2026-06-10), re-confirmed under ccloop run
`0d6e174d-541d-46cb-906b-406d39e484d5` on **2026-07-07** with sudo available.

### Precedent (sess14, 2026-06-10)
Documented verbatim in the header of `scripts/clyde_boot_recover.sh`. The SCST stack wedged
unrecoverably; leaked D-state `iscsi_conn_cleanup` threads blocked all serialized SCSI cmds; only a
host reboot cleared it. RULE 2 was written the SAME day precisely because sess14's
session-triggered "recovery" reboot HUNG the host and forced a manual HW reset — so sessions are
banned from rebooting or installing `@reboot` hooks to trigger one.
[[HOST-WEDGE-is-known-sess14-scst-recurring-only-host-reboot-clears]]

### The 2026-07-07 recurrence (ccloop 0d6e174d, sess2) — measured
- Root: **iscsi_scst session-teardown LIVELOCK**. 47 `iscsi_conn_cleanup` threads stuck; each qemu
  VM had an I/O worker thread stuck D-state (confirmed qemu pid 462356 tid 530633 = D) on target I/O
  → VMs couldn't terminate → undead (main thread Z, I/O thread D).
- nvme0n1 HEALTHY: no dmesg errors, 0 inflight, I/O merely frozen — a kernel-thread wedge, not
  hardware. Load climbing/WORSENING: 1032→1089 over ~15min, D-state count rising.
- **Trigger (DO NOT REPEAT):** tight-loop `virsh destroy` of ~32 VMs right after the 32-node
  `dlm_scaling` `valid_epoch` FUA storm left nodes with heavy in-flight LUN I/O → 64 concurrent
  iSCSI session teardowns livelocked. LESSON: never mass-`virsh destroy` many VMs during/after heavy
  shared-LUN I/O; quiesce mxfs / let I/O drain first, then destroy a few at a time (per
  `ccloop_reset.sh` per-node teardown), never a 32-wide parallel destroy. Also FIX `dlm_scaling@32`
  so 32-runs stop wedging nodes. [[HOST-WEDGE-clyde-iscsi-cleanup-livelock-2026-07-07-needs-manual-reset]]

### Recovery attempts — ALL FAILED (sudo available, still no clear)
`sudo -n true` rc=0, so root commands are runnable, but D-state kernel threads are unclearable from
userspace. Exhaustively confirmed ineffective (all with sudo):
- `sudo systemctl restart libvirtd` — did NOT reap the 32 undead qemus (D-state I/O thread can't exit
  → process can't die).
- iSCSI target disable/enable, `force_close` all sessions — no effect; `force_close` is itself the
  wedged path.
- `restart scst` — DO NOT. `scst.service` "failed" is a STALE 15h-old boot-time config-apply failure
  (ExecStart hit a FATAL opening `disk1` at 08:40 during boot) — a RED HERRING; SCST served the LUN
  fine all session via loaded kernel modules (`iscsi_scst`/`scst_vdisk`/`scst` all lsmod-loaded). A
  stop-phase would try to unload modules held by stuck threads → hang.
- `dlm_tool` not installed.
- Only UNVALIDATED/risky non-reboot idea (try ONLY if wedged and user unavailable):
  `sudo scstadmin -close_session ...` or force-abort via `/sys/kernel/scst_tgt/` to error the stuck
  I/O. Do not rely on it.

**Conclusion (sess14, re-confirmed 2026-07-07): only a host reboot clears it; the reboot is the
user's call; do NOT reboot and do NOT install `@reboot` hooks (RULE 2).**

### Post-reboot resume (when the USER reboots clyde)
`scripts/clyde_boot_recover.sh <run_id>` is the established resume helper (self-disarming `@reboot`
crontab): waits for scst + the `disk1b` target, re-establishes host iSCSI sessions
(`disk1b`/`disk1`/`disk1n2..n16` backing the test-VM passthrough disks — `virsh start` fails without
them), waits for `/src` NFS, resumes the ccloop run. run_id =
`0d6e174d-541d-46cb-906b-406d39e484d5`. A session must NOT reboot to invoke it.

### First actions for the next session (host-gate check)
1. `cut -d' ' -f1 /proc/loadavg` + `ps -eo stat,comm|awk '$1~/Z/&&$2~/qemu/'|wc -l` (or
   `grep -c iscsi_conn_cleanup`).
   - **load ~1000+ AND qemu zombies → STILL WEDGED** (not rebooted): concisely re-surface "clyde
     needs a manual reboot (RULE 2) — analysis complete, criteria host-gated" and do CODE-ONLY work.
     Do NOT re-attempt userspace recovery, do NOT reboot, do NOT write the ship marker (YES would be
     dishonest).
   - **load normal + 0 zombies → REBOOTED**: `virsh -c qemu:///system start test1..N`,
     `scripts/caw_preflight.sh N`, resume the sweep.

### While host-gated: analysis is COMPLETE — minimize cycles
Session 0d6e174d spent MANY cycles driving every answerable question to completion; it is ALL
recorded. Do NOT re-derive. SETTLED items (do not redo):
- **Host recovery** — reboot-only, exhaustively confirmed (above).
- **dlm_scaling@32 fix** — root + approach + traps + site + validation all settled in the
  authoritative single-reference note; the epoch fix is `valid_epoch` slot-aliasing-under-churn.
- **dir_reuse@16/32** — coherence-model-inherent (like GFS2/OCFS2), round-trip-latency-bound NOT
  storage-bound (~324 IOPS measured, NVMe at 12%); ~⅓ reducible via risky optimistic-read (only
  helps create), ⅔ necessary → budget-legitimate.
- **State on build 115CCA8C** (dedup + bast_wq default-on, built/deployed at `/src/mxfs/mxfs.ko`):
  caw pass rates 1/2/4/8 = 100%, 16 = 16/17 (dir_reuse perf holdout), 32 = 6/17. At 32/32:
  `strong_consistency`/`posix_multi`/`mmap_coherency`/`zero_silent_loss`/`dlm_fairness`/`precond_readiness`
  PASS 32/32; `dlm_scaling@32` FAIL (epoch). Ship marker NOT written (criteria not met).

Correct host-gated behavior (learned the hard way): do NOT spin generating ever-finer analysis or
peripheral busywork to satisfy the loop. The substantive work is genuinely complete; the blocker is a
physical host wedge only the user can clear. Each cycle: check the host, if still wedged truthfully
re-surface the host-gate, do not re-do analysis, do not write the marker. The moment clyde is
rebooted the playbook executes end-to-end. [[AAC-IF-HOST-STILL-WEDGED-analysis-COMPLETE-minimize-cycles]]
