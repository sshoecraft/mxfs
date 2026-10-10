---
name: trap-pve-live-migration-test-guest-needs-a-common-cpu-model-and-ssh-not-guest-exec
description: TRAP: physical pve1 (Xeon W3520) / pve2 (i3-8100): cpu=host guest dies at migration resume (KVM special registers); build guests refuse qemu-ga guest…
metadata:
  type: feedback
---

Testing live migration on the physical PVE pair (tests/pve_live_migrate.sh, 2026-10-09, 0.90.111):

- **A `cpu: host` guest cannot live-migrate between pve1 and pve2.** pve1 is a Xeon W3520 (Nehalem: no AES-NI, no AVX); pve2 is a Core i3-8100. The RAM copy completes, then the target QEMU dies at resume: `kvm: Putting registers after init: Failed to set special registers: Invalid argument`, and qm reports `resume failed - ... query-status failed - client closed connection`. That is a CPU-model mismatch, NOT a storage/MXFS failure. Use `qm set <id> --cpu x86-64-v2`; Proxmox's default `x86-64-v2-AES` will not even start on pve1. The packer build VMs (alma9-X1/X2) are `cpu: host`, so any clone of them needs the override.
- **The osimager/packer build guests' qemu-guest-agent refuses `guest-exec`** ("Command guest-exec has been disabled"), but `guest-network-get-interfaces` works. Drive the guest over ssh as root: its password is the same as the lab nodes' (`tools/mxfs_sshpass.sh <guest-ip> <cmd>` works unchanged).
- A writer that has been told to stop never acknowledges a pause; a harness's final check must wait for the writer's own exit marker instead.

Results with those fixed (same session): 6/6 migrations PASS data-wise, every fsynced file re-read from disk on the new host verified; downtime 0.4-2.5 s (unattributed at the time).
