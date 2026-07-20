---
name: feedback_pve_test_procedure
description: Correct order of operations when rebuilding/testing mxfs on PVE cluster
type: feedback
---

When rebuilding/testing mxfs on PVE, follow this exact order:

1. Delete all VMs on both pve1 and pve2 (`qm stop <id>; qm destroy <id> --purge`)
2. Remove the shared storage from PVE (`pvesm remove vms`)
3. Unmount on each node (`umount /mnt/pve/vms`)
4. rmmod on each node (`rmmod mxfs`)
5. Build (`make -C /src/mxfs clean && make -C /src/mxfs` on pve1)
6. insmod on each node (`insmod /src/mxfs/mxfs.ko`)
7. mkfs if needed (`echo y | /src/mxfs/tools/mkfs_mxfs /dev/sdb`)
8. Add storage back (`pvesm add mxfs vms --blockdevice /dev/sdb --shared 1 --content images,rootdir`)

**Why:** pvesm + pvestatd spin 100% CPU if mxfs mount hangs. Must remove storage BEFORE unmount/rmmod to prevent this. VMs must be deleted first because pvesm won't remove storage with active VMs.

**How to apply:** Any time you need to rebuild or test mxfs on the PVE cluster.
