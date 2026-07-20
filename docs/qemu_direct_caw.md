# QEMU Direct CAW via tcm_loop + iblock

How to present a local disk to QEMU VMs with SCSI Compare-And-Write (CAW) support, without iSCSI. Uses LIO's iblock backstore for CAW emulation and tcm_loop for local SCSI loopback.

## Why

MXFS CAW DLM requires SCSI CAW (opcode 0x89) on the shared block device. SATA SSDs don't support CAW natively — SATA has no equivalent command. QEMU's `scsi-hd` emulation also doesn't implement it. LIO's iblock layer emulates CAW in software (atomic read-compare-write with a semaphore), so we route the disk through LIO to gain CAW support.

## Chain

```
Physical SSD (/dev/sdX)
  → LIO iblock backstore (CAW emulation)
    → tcm_loop (local SCSI loopback, no network)
      → /dev/sdY on host (new SCSI device)
        → QEMU scsi-block passthrough (device='lun')
          → VM sees SCSI disk with CAW support
```

## Approaches That Don't Work

| Approach | Why It Fails |
|---|---|
| QEMU `device='disk'` (scsi-hd) | QEMU emulation doesn't implement CAW opcode 0x89 |
| QEMU `device='lun'` to SATA SSD | SG_IO passthrough works, but SATA device can't do CAW |
| vhost-scsi | Requires CONFIG_VHOST_SCSI in kernel (not built on Ubuntu 24.04 default) |

## Prerequisites

```bash
apt install targetcli-fb sg3-utils
```

Kernel modules needed: `target_core_mod`, `target_core_iblock`, `tcm_loop` (all in-tree on Ubuntu 24.04).

## Host Setup

### 1. Load tcm_loop

```bash
modprobe tcm_loop
```

Verify with `targetcli ls` — you should see `loopback` in the fabric list. Note: the `loopback` directory does NOT appear in raw `ls /sys/kernel/config/target/` — use `targetcli` to inspect.

### 2. Create iblock backstore

```bash
targetcli /backstores/block create name=ssd_870 dev=/dev/sda
```

Replace `/dev/sda` with your physical disk. The name is arbitrary — it becomes the SCSI model string visible inside VMs.

### 3. Create tcm_loop target and LUN

```bash
targetcli /loopback create naa.50000000000000a1
targetcli /loopback/naa.50000000000000a1/luns create /backstores/block/ssd_870
```

A new SCSI device appears on the host (check `dmesg` or `lsblk`):

```
scsi host14: TCM_Loopback
scsi 14:0:1:0: Direct-Access  LIO-ORG  ssd_870  4.0  PQ: 0 ANSI: 6
sd 14:0:1:0: [sdc] Attached SCSI disk
```

### 4. Verify CAW on host

```bash
# Write zeros to LBA 0
dd if=/dev/zero of=/dev/sdc bs=512 count=1 conv=fdatasync

# CAW: compare zeros, write 0xBB pattern
python3 -c "
import sys
sys.stdout.buffer.write(b'\x00' * 512 + b'\xBB' * 512)
" > /tmp/caw_test.bin

sg_raw -s 1024 -i /tmp/caw_test.bin /dev/sdc \
  89 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00
# Expected: SCSI Status: Good

# Verify write
dd if=/dev/sdc bs=512 count=1 | xxd | head -3
# Expected: all 0xBB

# Test miscompare (should fail)
sg_raw -s 1024 -i /tmp/caw_test.bin /dev/sdc \
  89 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00
# Expected: Sense key: Miscompare
```

## VM Configuration

### CRITICAL: Use System Libvirt (`qemu:///system`)

VMs **must** be managed via system libvirt (`sudo virsh`), NOT user-session libvirt
(`virsh` without sudo / `qemu:///session`).

SCSI passthrough (CAW, PR) requires `CAP_SYS_RAWIO` on the QEMU process. System
libvirt runs QEMU as root with full capabilities. User-session libvirt runs QEMU as
an unprivileged user with `CapEff=0x0` — all advanced SCSI commands silently fail with
"Aborted command, I/O process terminated" (ASC=0x06, ASCQ=0x10). Basic reads/writes
still work, making this failure deceptive.

### 1. VM must have a virtio-scsi controller

In the VM's libvirt XML:

```xml
<controller type='scsi' index='0' model='virtio-scsi'>
  <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
</controller>
```

### 2. Attach the tcm_loop device as device='lun'

Create an XML file (e.g., `/tmp/lun.xml`):

```xml
<disk type='block' device='lun'>
  <driver name='qemu' type='raw' cache='none' io='native'/>
  <source dev='/dev/sdc'/>
  <target dev='sda' bus='scsi'/>
  <shareable/>
  <address type='drive' controller='0' bus='0' target='0' unit='0'/>
</disk>
```

Attach to the VM (VM must be shut down for `scsi-block` to be used):

```bash
virsh attach-device VMNAME /tmp/lun.xml --config
virsh start VMNAME
```

The `<shareable/>` flag allows multiple VMs to share the same device. The `device='lun'` tells libvirt to use QEMU's `scsi-block` backend which passes SCSI CDBs through via SG_IO.

**Important**: Hot-attaching (`--live`) falls back to `scsi-hd` which does NOT pass through SCSI CDBs. The device must be in the config before the VM starts.

### 3. Fix AppArmor

QEMU's `scsi-block` backend uses SG_IO, which requires `CAP_SYS_RAWIO`. Ubuntu's libvirt AppArmor profiles deny this by default.

Find the VM's AppArmor profile:

```bash
ls /etc/apparmor.d/libvirt/libvirt-*.files | head
# or: virsh dumpxml VMNAME | grep uuid
```

Edit the main profile (NOT the `.files` one — that's auto-managed by libvirt):

```bash
# /etc/apparmor.d/libvirt/libvirt-<UUID>
profile libvirt-<UUID> flags=(attach_disconnected) {
  #include <abstractions/libvirt-qemu>
  #include <libvirt/libvirt-<UUID>.files>

  capability sys_rawio,    # ← ADD THIS LINE
}
```

Reload:

```bash
apparmor_parser -r /etc/apparmor.d/libvirt/libvirt-<UUID>
```

Without this fix, dmesg shows `apparmor="DENIED" capability=17 capname="sys_rawio"` and all SCSI CDB passthrough silently fails with "Aborted Command / I/O process terminated".

### 4. Apply to multiple VMs

Each VM has its own AppArmor profile (by UUID). To roll out to N VMs:

```bash
for vm in test1 test2 test3 ... ; do
  uuid=$(virsh dumpxml $vm | grep -oP '(?<=<uuid>).*(?=</uuid>)')
  profile="/etc/apparmor.d/libvirt/libvirt-${uuid}"

  # Add sys_rawio if not present
  grep -q "sys_rawio" "$profile" || \
    sed -i '/include.*\.files/a\  capability sys_rawio,' "$profile"

  apparmor_parser -r "$profile"

  # Attach disk (VM must be off)
  virsh attach-device $vm /tmp/lun.xml --config
done
```

## Verify CAW Inside VM

```bash
# Inside the VM:
dd if=/dev/zero of=/dev/sda bs=512 count=1 conv=fdatasync
python3 -c "
import sys
sys.stdout.buffer.write(b'\x00' * 512 + b'\xCC' * 512)
" > /tmp/caw_test.bin

sg_raw -s 1024 -i /tmp/caw_test.bin /dev/sda \
  89 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00
# Expected: SCSI Status: Good

# Read back (bypass page cache)
dd if=/dev/sda bs=512 count=1 iflag=direct | xxd | head -3
# Expected: all 0xCC
```

Note: `dd` without `iflag=direct` may return stale page cache data. Always use direct I/O or `drop_caches` when verifying writes.

## Cleanup

```bash
# Remove LUN and target
targetcli /loopback/naa.50000000000000a1/luns delete lun0
targetcli /loopback delete naa.50000000000000a1
targetcli /backstores/block delete ssd_870

# Unload module
rmmod tcm_loop
```

## Persistence

By default, targetcli saves config to `/etc/target/saveconfig.json` on exit. To restore after reboot:

```bash
systemctl enable rtslib-fb-targetctl
```

Or recreate manually — the setup is fast (3 commands).
