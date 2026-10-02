---
name: trap-the-host-fits-14-rig-vms-under-load-so-six-release-boards-cannot-run-at-once
description: CORRECTED 2026-10-01: rig VMs run at 2.5 GiB (balloon; 4 GiB max) x 4 vCPU. 28 nodes = 70 GiB fits 94 GiB; the real limit is CPU (112 vCPU on 56 core…
metadata:
  type: feedback
---

**Measured 2026-10-01 (virsh dominfo test1/3/9/17/25):** Max memory 4194304 KiB, Used memory 2621440 KiB, 4 vCPUs. The earlier version of this note said rig VMs are "4 GiB" and that six release boards (28 nodes) need 112 GiB on the 94 GiB host. That counted the balloon ceiling, not the allocation; the user caught it.

**What actually holds:**
- Memory: 28 nodes x 2.5 GiB = 70 GiB, which fits 94 GiB with the rig alone up. It stops fitting if the balloons are raised toward 4 GiB, or with platform sets (8 x 2.5+ GiB each) up at the same time.
- CPU: 28 x 4 = 112 vCPU on 56 cores (2x oversubscribed). The boards grade pace (native-XFS yardsticks, per-row budgets), so a fully parallel six-board run risks pace failures caused by host contention. Throughput rows already take a host-wide lock for this reason.
- Platform sets compiling DKMS at 8 nodes oversubscribe on their own (see trap-two-8-node-platform-sets-compiling-dkms-at-once...).

**Do:** check `virsh dominfo <vm>` Used memory before sizing a parallel run; don't quote the max.
