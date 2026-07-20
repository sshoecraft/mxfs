---
name: project-caw-priority-enterprise-vmware-proxmox-san
description: Goal = BOTH tcp+caw at 100%, but CAW is priority: it's the enterprise ship target (VMware→Proxmox migration, VMs on shared enterprise SAN LUN). TCP i…
metadata:
  type: project
---

## Why CAW is the priority (user directive, sess58/59, 2026-06-22)

The product goal is **both** TCP and CAW transports passing 100% of the
criteria suite. But **CAW is the priority** because it is the actual
enterprise shipping target:

- Target customer: enterprises **migrating off VMware onto Proxmox**.
- They run **VMs whose disk images live on a shared enterprise SAN LUN**.
- Multiple Proxmox hosts concurrently access that shared LUN → that is
  exactly the CAW (SCSI Compare-And-Write disk-based DLM) use case.
- TCP DLM is the must-keep **fallback** (used when hardware/SCSI CAW is
  unreliable), and is perf-limited >16 nodes — see
  [[project_caw_is_load_bearing]]. It is NOT what the enterprise customer
  runs day-to-day.

### Implications for test/perf strategy
- Prioritize CAW correctness + perf over building out a TCP node-count
  scaling matrix. Scaling work should climb node counts on CAW (the
  transport that ships at scale), not TCP.
- The real enterprise workload profile is **VM-on-SAN**: fewer, very
  large files (qcow2/raw images), concurrent random I/O, O_DIRECT from
  multiple hosts — quite different from the metadata-heavy
  rsync/dir-reuse criteria tests. The criteria suite proves
  coherence/correctness; a CAW perf pass against the VM-on-SAN profile
  (under RULE 0's 2× native-XFS ceiling) is wanted eventually, after
  2-node CAW correctness is solid.

### Current roadmap decision
2-node TCP is done (17/17, build 60EFBE5E, [[sess58-CRITERION-MET-2tcp-17of17-8consecutive]]).
Next step chosen: **2-node CAW to 100%** (change transport, hold node
count fixed = single-variable step), THEN scale CAW up node counts. The
sess58 inode-lock fixes (AG↔dir ABBA, ilock_nowait dir-DLM) are in
xfs/xfs_inode.c = transport-independent, so CAW inherits them.
