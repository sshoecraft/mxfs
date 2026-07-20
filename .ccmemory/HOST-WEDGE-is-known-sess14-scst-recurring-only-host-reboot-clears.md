---
name: HOST-WEDGE-is-known-sess14-scst-recurring-only-host-reboot-clears
description: The 2026-07-07 host wedge is the KNOWN sess14 SCST/iscsi_conn_cleanup D-state wedge (see scripts/clyde_boot_recover.sh header). Userspace CANNOT clea…
metadata:
  type: project
---

## The host wedge is the KNOWN, RECURRING sess14 SCST wedge — only a host reboot clears it

Cross-ref [[HOST-WEDGE-clyde-iscsi-cleanup-livelock-2026-07-07-needs-manual-reset]] (this session's full
diagnosis + exhausted recovery). This memo adds the PRECEDENT so no future session re-hunts recovery.

### It is documented in `scripts/clyde_boot_recover.sh` (written sess14, 2026-06-10):
Verbatim from its header: "the SCST target stack wedged unrecoverably: leaked D-state
iscsi_conn_cleanup kernel threads pinned per-device command counts so every strictly-serialized SCSI cmd
(CAW, WRITE SAME) blocked forever in EXEC_CHECK_BLOCKING; scst.service hung 'deactivating'; only a host
reboot clears kernel-thread state."

### CONCLUSION (established sess14, re-confirmed 2026-07-07 with sudo):
- This wedge = leaked D-state `iscsi_conn_cleanup` kernel threads. It is UNRECOVERABLE from userspace.
  Confirmed ineffective 2026-07-07 (all with sudo): `force_close` all sessions, iSCSI target
  disable/enable, `libvirtd restart`. force_close is itself the wedged path. `dlm_tool` not installed.
- **ONLY A HOST REBOOT clears it.** RULE 2 (written 2026-06-10, the SAME day, precisely because sess14's
  session-triggered recovery reboot HUNG the host and forced a manual HW reset) FORBIDS any session from
  rebooting clyde. ⇒ the reboot is the USER'S call. Do NOT reboot; do NOT install @reboot hooks to trigger
  one (RULE 2 bans that too).
- Trigger to AVOID: mass/tight-loop `virsh destroy` of many VMs while they have heavy in-flight shared-LUN
  I/O (e.g. right after a 32-node dlm_scaling FUA storm). Quiesce first (stop mxfs / let I/O drain), and
  destroy VMs a few at a time — see ccloop_reset.sh's per-node teardown pattern, not a 32-wide parallel destroy.

### POST-REBOOT RESUME (when the USER reboots clyde):
`scripts/clyde_boot_recover.sh <run_id>` is the established resume helper (self-disarming @reboot crontab):
waits for scst + the disk1b target, re-establishes host iSCSI sessions (disk1b/disk1/disk1n2..n16 that
back the test-VM passthrough disks — virsh start fails without them), waits for /src NFS, resumes the
ccloop run. This run_id = 0d6e174d-541d-46cb-906b-406d39e484d5. The user (or a session, at the user's
direction) may install it; a session must NOT reboot to invoke it.

### NEXT SESSION: check load (`cut -d' ' -f1 /proc/loadavg`). If ~1000+ with qemu undead → STILL WEDGED,
host not yet rebooted → cluster-independent work only (implement the dlm_scaling gen-gate design +
dir_reuse perf design, ready to test on reset). If load normal → rebooted → `virsh start test1..N`,
`caw_preflight.sh N`, resume the sweep. Build 115CCA8C (dedup+bast_wq default-on) is validated + deployed.
