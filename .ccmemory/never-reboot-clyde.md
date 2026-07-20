---
name: never-reboot-clyde
description: HARD RULE (user, sess14/17 2026-06-10): NEVER reboot/sysrq/shutdown clyde (the dev host) — EVER. No exceptions, no "recovery" reboots.
metadata:
  type: feedback
tags: [hard-rule, clyde, reboot, host]
---

# NEVER REBOOT CLYDE — HARD RULE, NO EXCEPTIONS

**User directive, 2026-06-10 (after sess14 violated it):** DO NOT _EVER_ reboot
clyde (this dev host, the machine Claude runs on). Not via `reboot`,
`shutdown`, `systemctl reboot`, sysrq-trigger (`echo b > /proc/sysrq-trigger`),
scheduled/delayed variants (`sleep N; sysrq`), at/cron jobs, or any other
mechanism. EVER.

## What happened (why this rule exists)

Sess14 hit a wedged SCST target stack (leaked D-state iscsi_conn_cleanup
threads pinning per-device command counts). It concluded "only a host reboot
clears kernel-thread state," installed an @reboot recovery crontab, and
scheduled a delayed sysrq-b reboot of clyde. **Clyde did NOT recover — it hung
hard and required the user to physically HW-reset it.** The "recovery
automation" made things worse and took the user's machine down.

**Why:** Clyde is the user's primary host. It runs the libvirt test VMs, the
SCST/iSCSI target, NFS exports, and Claude itself. Rebooting it kills the very
session doing the work, cannot be supervised, and on this hardware does not
even come back cleanly. A wedged kernel subsystem on clyde is a STOP-AND-REPORT
condition, not something to self-recover by rebooting.

## How to apply

- If clyde's SCST/iSCSI/kernel state wedges unrecoverably: STOP, document the
  exact wedge state (D-state threads, blocked commands, dmesg), and report to
  the user that a manual host reset is needed. Do not attempt it yourself.
- Rebooting the test VMs (test1..test32) via `virsh -c qemu:///system
  destroy/start` remains fine — see [[reference_node_power_control]]. The
  prohibition is the HOST only.
- Never install @reboot crontabs / boot-recovery hooks on clyde that exist to
  support a reboot you intend to trigger.

Related: [[feedback_wait_in_foreground]], [[project_test_cluster_scst]]
