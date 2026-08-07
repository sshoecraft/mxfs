---
name: storage-investigation
description: Storage investigation: iSCSI + shared-disk performance characterisation of the lab rig.
metadata:
  type: project
---

# Storage Investigation — iSCSI & Shared Disk Performance

## Current State (as of 2026-02-22)

### Infrastructure
- Dev machine: 192.168.120.1, NVMe local storage
- ESX hosts: esxhost1.localdomain (192.168.1.251), esxhost2.localdomain (192.168.1.252)
- Both ESX hosts are Workstation VMs at ~/vms/vmware/esxhost/ and ~/vms/vmware/esxhost2/
- vCenter: vcenter.localdomain (192.168.1.250)
- ESXi version: 8.0.2 build-22380479
- Bridge br0: 192.168.120.1, MTU 9000 (connects to ESX hosts and VMs)
- Management NIC enp6s0: 192.168.1.166, MTU 1500 (must stay 1500! ESX management network)

### Shared Storage Setup
- iSCSI target: LIO on dev machine, block backstore + loopback with direct-io
- Image: /home/steve/iscsi-lun.img (50GB, preallocated with dd)
- Loopback: `sudo losetup --direct-io=on -f /home/steve/iscsi-lun.img` → /dev/loop0
- Target IQN: iqn.2024-01.localdomain.dev:mxfs
- Portal: 192.168.120.1:3260
- LUN NAA: naa.600140529a4fe6e7aaf45bfb09ec952c
- targetcli config saved to /etc/rtslib-fb-target/saveconfig.json
- **NOTE**: loopback --direct-io does NOT persist across reboot. Need to recreate loopback before starting target.

### ESXi iSCSI Initiator Config
- Both hosts: vmhba65 (iscsi_vmk), software iSCSI adapter
- Discovery target: 192.168.120.1:3260 on both hosts
- esxhost1: vmk1 at 192.168.120.11/24, MTU 9000, bound to vmhba65, on vSwitch1/portgroup "iSCSI"
- esxhost2: vmk1 at 192.168.120.12/24, MTU 9000, bound to vmhba65, on vSwitch1/portgroup "iSCSI"
- SSH enabled on both hosts (TSM-SSH service)

### RDM Setup
- VMFS datastores for RDM mapping files:
  - esxhost1: "rdm1" (2GB VMFS on local VMDK scsi0:2)
  - esxhost2: "rdm2" (2GB VMFS on local VMDK scsi0:2)
- RDM mapping files created via vmkfstools:
  - esxhost1: /vmfs/volumes/rdm1/mxfs_shared.vmdk → naa.600140529a4fe6e7aaf45bfb09ec952c
  - esxhost2: /vmfs/volumes/rdm2/mxfs_shared.vmdk → naa.600140529a4fe6e7aaf45bfb09ec952c
- All 32 test VM VMX files updated with:
  ```
  scsi0:1.present = "TRUE"
  scsi0:1.fileName = "/vmfs/volumes/rdm1/mxfs_shared.vmdk"  (odd VMs)
  scsi0:1.fileName = "/vmfs/volumes/rdm2/mxfs_shared.vmdk"  (even VMs)
  scsi0:1.deviceType = "scsi-hardDisk"
  scsi0:1.sharing = "multi-writer"
  ```
- VMs see it as /dev/sdb (50GB, model: mxfs_lun)

### Shared Workstation VMDK (for future use)
- ~/vms/vmware/esxhost/shared.vmdk — preallocated 50GB, shared between both ESX host VMs
- Both ESX host VMX files have: scsi0:1.sharing = "multi-writer", disk.locking = "FALSE"
- Shows up as mpx.vmhba0:C0:T1:L0 on both ESX hosts (50GB, local SSD)
- Has no NAA identifier — cannot be used for RDM directly
- Could be formatted as VMFS for shared VMDK approach (not currently used)

### Performance Benchmarks

| Configuration | Read | Write | Notes |
|---|---|---|---|
| Raw NVMe (dd on file) | 2,500 MB/s | 2,100 MB/s | Baseline |
| Raw loopback+DIO (no LIO) | 2,600 MB/s | 2,100 MB/s | Loopback adds no overhead |
| Local iSCSI loopback, block+DIO | 562 MB/s | 847 MB/s* | LIO overhead; *write suspicious |
| Guest iSCSI, fileio, MTU 1500 | 198 MB/s | 85 MB/s | Original config |
| Guest iSCSI, fileio, MTU 9000 | 198 MB/s | 158 MB/s | Jumbo frames help writes |
| Guest iSCSI, block+DIO, MTU 9000 | 260 MB/s | 195 MB/s | Best guest config |
| **ESXi RDM, vmk1 MTU 9000** | **117 MB/s** | **145 MB/s** | Current — SLOWER than guest |
| ESXi RDM, vmk0 MTU 1500 (wrong port) | 110 MB/s | 18 MB/s | Before iSCSI binding fix |

### OPEN ISSUE: ESXi RDM iSCSI slower than guest iSCSI
- ESXi initiator (117/145) is slower than guest initiator (260/195)
- Need to investigate why — possible causes:
  - ESXi VMkernel TCP/iSCSI stack less optimized for software targets
  - RDM passthrough overhead
  - ESXi iSCSI tuning parameters (queue depth, max recv/send segments)
  - Single iSCSI session vs multiple
- **TODO**: Web search for ESXi iSCSI performance tuning, compare with guest approach

### Bug Z Self-Deadlock Fix — IN PROGRESS
- **Root cause**: cache_get_locked() in libmxfs/inode_cache.c enters BAST wait loop when bast_pending=true.
  If the calling thread already holds a refcount (nested call, e.g. mxfs_dir_add_entry → flush_dir_immediate
  both call cache_get_locked on the same dir inode), it self-deadlocks: the wait loop needs refcount==0
  but the outer caller holds refcount==1.
- **Fix applied**: At line ~622 in inode_cache.c, added check: if bast_pending && refcount > 0, skip the
  wait loop (allow nested get). BAST completes when the outermost put() drops refcount to 0.
  Added debug log for this path. The existing timeout/eviction logic is now inside an else block for
  the refcount==0 case only.
- **Build status**: Compiled clean on 6.8 kernel (dev machine). NOT YET built on 6.1 (test nodes).
- **Test status**: NOT YET TESTED. Previous attempt (before this fix) deadlocked on 4-node concurrent
  file creation. Need to: build on test1, deploy to all 4 nodes, run concurrent touch test.
- **Reproducer**: On each of 4 nodes simultaneously: `for i in $(seq 1 50); do touch /mnt/shared/testN_file_$i; done`
- XFS needs to be reformatted on /dev/sdb before MXFS testing

### SCSI-3 PR Testing via RDM
- RDM setup passes SCSI commands directly to the iSCSI LUN — should support SCSI-3 PR
- This has NOT been tested yet with the RDM path
- Guest iSCSI approach has been working with SCSI-3 PR all along
- Worth testing: does MXFS SCSI-3 PR (register/reserve/preempt) work through the ESXi RDM path?
- If RDM PR works, we could use RDM for PR fencing + guest iSCSI for data I/O (but that's complex)
- Simplest approach: just use guest iSCSI for everything (faster, proven to work with PR)

### Current VM State (end of session)
- test1-test4: POWERED ON, RDM attached, /dev/sdb visible (50GB mxfs_lun)
- test5-test32: powered off, VMX files updated with RDM entries
- ESX hosts: both up, iSCSI initiators configured with vmk1 on 192.168.120.x MTU 9000
- iSCSI target: running on dev machine (block backstore, /dev/loop0, DIO)
- /dev/sdb has raw data from benchmark dd — needs `mkfs.xfs -f /dev/sdb` before MXFS use
- mxfs.ko: built on dev machine (6.8), NOT yet built on test nodes (6.1)
- NFS probably not mounted on test nodes (they were freshly booted)

### Startup Checklist for Next Session
1. Symlink password file: `ln -s ~/.mxfs/pass /tmp/.mxfs_pass`
2. Verify loopback+iSCSI target running: `sudo targetcli ls /`
   - If not: `sudo losetup --direct-io=on -f /home/steve/iscsi-lun.img && sudo systemctl restart rtslib-fb-targetctl`
3. Verify br0 MTU: `ip link show br0` — should be 9000
4. Keep enp6s0 at MTU 1500! (management network)
5. Power on ESX hosts, verify "connected" in vCenter
6. Power on test VMs, verify /dev/sdb visible
7. Set MTU 9000 on test VMs: `sudo ip link set eth0 mtu 9000` (doesn't persist)
8. Mount NFS on test nodes: `sudo mount -t nfs 192.168.120.1:/home/steve/src/mxfs /mnt/mxfs-src`
9. Build on test1: `cd /mnt/mxfs-src/v2 && make clean && make`
10. Format XFS: `sudo mkfs.xfs -f /dev/sdb` (on one node only, others not connected)
11. Deploy and test Bug Z fix (4-node concurrent file creation)

### Decision Needed Next Session
- **Storage approach**: Guest iSCSI (faster, 260/195 MB/s, proven) vs ESXi RDM (117/145 MB/s, needs PR test)
- Could keep RDM config in VMX files and also use guest iSCSI — just don't mount both simultaneously
- Recommend: test SCSI-3 PR through RDM once, then decide. If guest iSCSI PR still works (it should),
  switch back to guest iSCSI for all testing since it's 2x faster.
