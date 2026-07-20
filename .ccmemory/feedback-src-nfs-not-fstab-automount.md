---
name: feedback-src-nfs-not-fstab-automount
description: /src NFS must NOT be a boot-time fstab auto-mount on the test VMs (hard NFS can hang boot if QNAP down). Mount /src only in the VM buildup/prep step.
metadata:
  type: feedback
tags: [infra, nfs, src, vm-buildup, fstab, boot]
---

## /src must be mounted by the buildup/prep step, NOT fstab auto-mount (user, 2026-07-05)

**Why:** `/src` is QNAP NFS (192.168.1.4:/src). If it's in the guest `/etc/fstab`
(seen as `192.168.1.4:/src /src nfs defaults,_netdev 0 0`), `defaults` implies a
`hard` NFS mount — if the QNAP is unreachable at boot the mount unit retries
forever and can hang/severely delay VM boot (or drop to emergency). A shared-LUN
FS host must not be held hostage to an NFS dependency at boot.

**How to apply:** Mount `/src` ONLY as part of the VM buildup / node-prep step
(the prep scripts `tools/prep_node.sh`, `tools/prep_tcm_node_scst.sh`, and
`tests/criteria/lib.sh` ENSURE_NFS already do this — retry-mount at bring-up,
not boot). Remove `/src` from guest `/etc/fstab` so it never auto-mounts. Keep
the fleet consistent (as of 2026-07-05 it was inconsistent — some VMs had the
fstab line, some didn't; ~16/32 auto-mounted).

Do NOT touch clyde's NFS *exports* / server side ([[infra-src-is-qnap-nfs-do-not-touch-exports]]);
this is purely about the guest-side mount trigger. Relates to
[[caw-test-3-conditions-and-script-inventory]] (bring-up scripts).
