---
name: feedback_sudo_virsh
description: MUST use sudo virsh for all VM operations — session libvirt breaks CAW
type: feedback
---

All virsh commands MUST use `sudo virsh` (qemu:///system), NEVER bare `virsh` (qemu:///session).

**Why:** User-session libvirt runs QEMU as unprivileged user with CapEff=0x0. SCSI passthrough (CAW, PR) requires CAP_SYS_RAWIO. System libvirt runs QEMU as root. Using bare `virsh` silently breaks all SCSI CAW operations with "Aborted command, I/O process terminated" — basic reads/writes still work, making the failure deceptive.

**How to apply:** Every `virsh` command in scripts or direct invocation must be `sudo virsh`. This is documented in docs/qemu_direct_caw.md (lines 97-106) and docs/qemu_tcm_loop_setup.md (lines 10-13). Read the project docs before touching the test environment.
