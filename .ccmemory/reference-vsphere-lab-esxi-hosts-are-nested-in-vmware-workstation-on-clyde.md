---
name: reference-vsphere-lab-esxi-hosts-are-nested-in-vmware-workstation-on-clyde
description: esxhost1/esxhost2 are nested ESXi VMs in VMware Workstation on clyde (~/vms/vmware); vstest guests are two hypervisors deep and soft-lock under clyde…
metadata:
  type: reference
tags: [vsphere, lab, nested-virt, rig]
---

User, 2026-09-23: "the esxhost is a virtual nested host running on vmware workstation ~/vms/vmware/".

**Layout (read from the .vmx files):**
- `~/vms/vmware/esxhost/esxhost.vmx` — displayName esxhost1, 14 vCPU, 16 GB, `sched.cpu.affinity = "0-31"`, `vhv.enable = TRUE`.
- `~/vms/vmware/esxhost2/esxhost2.vmx` — esxhost2, 14 vCPU, 16 GB, `sched.cpu.affinity = "14-21,42-49"` (16 clyde threads, hyperthread pairs, for 14 vCPUs).
- `~/vms/vmware/vcenter/vcenter.vmx` — vCenter, 4 vCPU.
- vCenter "idle host" numbers describe the ESXi layer only; clyde's own load (libvirt rig VMs, NFS, other jobs) decides whether the ESXi vCPUs run at all.

**What it looks like when the outer layers starve a guest:** vstest1 (Ubuntu 24.04, 6.8.0-53) soft-locked on EVERY CPU, idle tasks included ("CPU#1 stuck for 23s! [swapper/1:0]") during boot, before any MXFS mount; vCenter showed all 4 vCPUs at 100% (9580 MHz) with ping dead. An idle task tripping the soft-lockup detector means its vCPU was not being run — the signature of the hosting layer, not of guest code.

**How to apply:**
- Never read a vSphere guest's timing (lease expiry, scan windows, soft lockups, "hung" mounts) as an MXFS result without first checking that guest's console / dmesg for soft lockups on idle CPUs over the same interval, and clyde's load.
- A guest clock that jumps forward after a stall expires every MXFS deadline at once on resume (lease self-fence, overdue work items), which reads exactly like an MXFS renewal bug.
- A reset from `govc vm.power -reset` and one from the vSphere client are the same operation.
