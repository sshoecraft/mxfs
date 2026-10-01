---
name: trap-the-host-fits-14-rig-vms-under-load-so-six-release-boards-cannot-run-at-once
description: TRAP (0.90.37): rig VMs are 4 GiB / 4 vCPU; six release boards need 28 nodes = 112 GiB on a 94 GiB host. Groups g2/g4/g8 (14 nodes) run one class at…
metadata:
  type: feedback
---

The Part B plan assumed `{2,4,8} x {net/mesh, disk/caw}` = 28 nodes could run on test1..28 at once. It can't. `virsh dominfo` puts every rig VM at 4 GiB and 4 vCPUs. clyde has 94 GiB total, with about 61 GiB available while 9 VMs ran, and 56 cores.

What does fit is one class's three release boards: groups g2=test1-2, g4=test3-6 and g8=test7-14. That is 14 nodes, 56 GiB and 56 vCPUs, and it is recorded in the lab file's `group` line. Run `net/mesh` first, then `disk/caw` on the same groups.

Before sizing any parallel rig layout, check `virsh dominfo` and `free -g`. Don't assume the node count is the only limit. The platform sets (pve9-*, alma9-*, and so on) are separate VMs, which is why `scripts/lab_power.sh` powers sets up and down.
