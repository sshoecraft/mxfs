---
name: HOST-WEDGE-clyde-iscsi-cleanup-livelock-2026-07-07-needs-manual-reset
description: URGENT: clyde HOST WEDGED 2026-07-07 (ccloop 0d6e174d sess2). iscsi_scst session-teardown livelock: stuck D-state kernel threads (qemu I/O + 47 iscsi…
metadata:
  type: project
---

## ⚠️ CLYDE HOST WEDGED — needs MANUAL RESET (user's call, RULE 2) — 2026-07-07

### The wedge (measured, WORSENING: load 1032→1089 over ~15min, D-state count climbing, nvme I/O frozen)
- Root: **iscsi_scst (SCST iSCSI target) session-teardown LIVELOCK**. 47 `iscsi_conn_cleanup` kernel
  threads stuck; each qemu VM has a worker thread stuck **D-state** (confirmed: qemu pid 462356 tid
  530633 = D) on I/O to the target → VMs can't terminate → show as undead (main thread Z, I/O thread D).
- nvme0n1 HEALTHY (no dmesg errors, 0 inflight, I/O just frozen). It's a kernel-thread wedge, not hardware.
- TRIGGER (DO NOT REPEAT): tight-loop `virsh destroy` of ~32 VMs right after the 32-node dlm_scaling
  valid_epoch FUA storm left nodes with heavy in-flight LUN I/O. 64 concurrent iSCSI session teardowns
  livelocked. **LESSON: never mass-`virsh destroy` many VMs during/after heavy shared-LUN I/O; destroy a
  few at a time with pauses, or quiesce I/O first. And FIX dlm_scaling@32 so 32-runs don't wedge nodes.**

### RECOVERY ATTEMPTED — FAILED (I have sudo, but D-state kernel threads are unclearable w/o reboot):
- **sudo IS available** (`sudo -n true` rc=0). Earlier systemctl "Interactive auth required" was just
  missing sudo. So the next session CAN run root commands — BUT:
- `sudo systemctl restart libvirtd` → did NOT reap the 32 undead qemus (their D-state I/O thread can't
  exit → process can't die). Confirms kernel-level wedge.
- `scst.service` shows "failed" BUT that is a STALE 15h-old boot-time config-apply failure (ExecStart
  hit a FATAL opening 'disk1' at 08:40 during boot) — **RED HERRING**: SCST served the LUN fine all
  session via the loaded kernel modules (iscsi_scst/scst_vdisk/scst all lsmod-loaded). Do NOT
  `restart scst` expecting a fix — a stop-phase would try to unload modules held by stuck threads → hang.
- D-state kernel threads (qemu I/O, iscsi_conn_cleanup) CANNOT be killed by any userspace command even
  with sudo. Only the blocking condition resolving (it's worsening, not) or a host reboot (RULE 2 FORBIDS)
  clears them. ⇒ genuinely needs a MANUAL HOST RESET (user's call).

### FOR THE NEXT SESSION — FIRST ACTIONS
1. Check `cut -d' ' -f1 /proc/loadavg` + `ps -eo stat,comm|grep -c iscsi_conn_cleanup`. If load ~1000 and
   threads stuck → STILL WEDGED: the user must have reset clyde. If not reset, report again; do CODE-ONLY
   work (dlm_scaling@32 epoch fix per [[caw-HYPOTHESIS-dlm_scaling32-epoch-is-slot-aliasing-under-churn]]).
2. If clyde was RESET (load normal, no zombies): start VMs (`virsh -c qemu:///system start test1..N`),
   `scripts/caw_preflight.sh N`, resume. Build 115CCA8C already at /src/mxfs/mxfs.ko (dedup+bast_wq
   default-on). POSSIBLE non-reboot recovery to try IF wedged-but-user-unavailable: `sudo scstadmin
   -close_session ...` or force-abort via /sys/kernel/scst_tgt/ to error the stuck I/O — UNVALIDATED/risky.

### CRITERIA PROGRESS (safe in criteria.json + memories): 16/caw=16/17 (dir_reuse perf holdout). 32/caw:
strong_consistency/posix_multi/mmap_coherency/zero_silent_loss/dlm_fairness/precond_readiness PASS 32/32
(build 115CCA8C). dlm_scaling@32 FAIL (epoch). Marker NOT written (criteria NOT met).
See [[caw-session-STATE-2026-07-07-build-115CCA8C-16of17-and-32-progress]].
