# QEMU TCM Loop Node Setup

Worker runbook for preparing a QEMU/KVM test VM with tcm_loop SCSI LUN passthrough.
Read this document and follow it for the assigned node(s). Make decisions based on
current state — don't do unnecessary work.

## Environment

- **Host machine**: clyde (192.168.1.166), the dev machine running libvirt
- **Libvirt connection**: `qemu:///system` (system libvirt, NOT session). All `virsh`
  commands MUST use `sudo virsh`. System libvirt runs QEMU as root with `CAP_SYS_RAWIO`,
  which is required for SCSI passthrough commands (CAW, PR). User-session libvirt
  (`qemu:///session`) runs QEMU as unprivileged user and CAW/PR will fail.
- **Shared SCSI device (host)**: `/dev/sdc` — Samsung 870 1.8TB via LIO iblock + tcm_loop
- **Shared SCSI device (guest)**: Determined from VM XML `<target dev='...' bus='scsi'/>`
  - Read the target dev name from the XML (e.g., `sda`). The guest device is `/dev/{target_dev}`.
  - Verify this device exists and is a block device inside the guest.
- **NFS server**: `192.168.1.4:/src` mounted at `/src` inside guests
- **Module path (on NFS)**: `/src/mxfs/mxfs.ko`
- **VM credentials**: root / <REDACTED-ROTATED>
- **Password file**: `/tmp/.mxfs_pass` (on host)
- **SSH tool**: `/src/mxfs/tools/mxfs_sshpass.sh HOSTNAME /tmp/.mxfs_pass "COMMAND"`
- **VMs**: test1 through test32, Ubuntu 24.04, bridged to br0

## Step 1: Verify VM XML Configuration (runs on host)

Check the VM's persistent (inactive) XML for three requirements:

1. **Block device type**: `<disk type='block' device='lun'>` (NOT `device='disk'`)
2. **Source device**: `<source dev='/dev/sdc'/>` (NOT `/dev/sdb` or anything else)
3. **SCSI controller**: `<controller type='scsi' ... model='virtio-scsi'>`

To check:
```
sudo virsh dumpxml VMNAME --inactive
```

**If all three are correct** → skip to Step 2, no XML changes needed.

**If any are wrong** → fix the XML:
```
sudo virsh dumpxml VMNAME --inactive > /tmp/VMNAME.xml
# Edit /tmp/VMNAME.xml to fix the issues:
#   - Change device='disk' to device='lun' on the block disk (NOT the qcow2 boot disk)
#   - Change source dev to /dev/sdc
#   - Ensure virtio-scsi controller exists
sudo virsh define /tmp/VMNAME.xml
```

After defining, verify the fix took:
```
sudo virsh dumpxml VMNAME --inactive | grep -A5 "type='block'"
```

**If the VM is currently running and XML was changed** → the running instance has stale
config. It must be destroyed and restarted:
```
sudo virsh destroy VMNAME
```
(Step 2 will start it.)

**If the VM is currently running and XML was already correct** → do NOT restart it.
Proceed to Step 2.

## Step 2: Ensure VM is Running (runs on host)

Check VM state:
```
sudo virsh domstate VMNAME
```

**If running** → skip to Step 3.

**If shut off** → check for stale QEMU processes holding the qcow2 lock:
```
ps aux | grep "guest=VMNAME," | grep -v grep
```
If a stale process exists, kill it:
```
kill PID
# Wait a moment for the lock to release
sleep 2
```

Start the VM:
```
sudo virsh start VMNAME
```

**If start fails with "Permission denied" on the qcow2 file** → fix permissions:
```
sudo chmod 666 /home/steve/vms/qemu/VMNAME/VMNAME
sudo virsh start VMNAME
```

**If start fails with "Failed to get write lock"** → there's still a stale QEMU process.
Find and kill it (check for root-owned processes too):
```
ps aux | grep "guest=VMNAME," | grep -v grep
sudo kill PID
sleep 2
sudo virsh start VMNAME
```

## Step 3: Wait for SSH (runs on host)

After the VM is running (whether it was already running or just started), wait for SSH:

```
# Poll SSH availability (up to 60 seconds)
for i in $(seq 1 30); do
    nc -w2 -z VMNAME 22 2>/dev/null && break
    sleep 2
done
```

Verify SSH works:
```
/src/mxfs/tools/mxfs_sshpass.sh VMNAME /tmp/.mxfs_pass "hostname"
```

If SSH doesn't come up within 60 seconds, report FAIL.

## Step 4: Mount NFS (runs on guest via SSH)

All remaining steps run inside the guest via SSH.

```
/src/mxfs/tools/mxfs_sshpass.sh VMNAME /tmp/.mxfs_pass "COMMAND"
```

Check if NFS is already mounted:
```
mountpoint -q /src
```

**If mounted** → verify the module file is accessible: `ls -la /src/mxfs/mxfs.ko`
**If not mounted** →
```
mkdir -p /src
mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp,rsize=1048576,wsize=1048576
```

If NFS mount fails, report FAIL with the error.

## Step 5: Verify the SCSI Device (runs on guest via SSH)

The expected guest device name comes from the VM XML. In Step 1, the SCSI LUN disk
has a `<target dev='XYZ' bus='scsi'/>` element. The guest device is `/dev/XYZ`
(e.g., if target dev is `sda`, the guest device is `/dev/sda`).

Verify the device exists and is a block device inside the guest:
```
[ -b /dev/DEVICE ] && echo "DEVICE_OK" || echo "DEVICE_MISSING"
```

Also verify it's accessible (can read from it):
```
dd if=/dev/DEVICE bs=512 count=1 of=/dev/null 2>&1
```

**If device missing or not readable** → the SCSI LUN isn't visible in the guest. This
means the XML config or QEMU launch is wrong. Report FAIL — do not try to fix from
inside the guest.

## Step 6: Verify CAW (runs on guest via SSH)

Compare-And-Write must work for the CAW DLM transport.

```
dd if=DEVICE bs=512 count=1 skip=200000 of=/tmp/caw_test 2>/dev/null
cat /tmp/caw_test /tmp/caw_test > /tmp/caw_buf
sg_compare_and_write --in=/tmp/caw_buf --lba=200000 --num=1 --xferlen=1024 DEVICE 2>&1
```

**If RC=0** → CAW works. Proceed.

**If RC != 0** → CAW is broken. Common causes:
- "Aborted command, I/O process terminated" (ASC=0x06, ASCQ=0x10): The SCSI command
  was rejected. On the HOST, check IN THIS ORDER:
  1. Is QEMU running as root? (`ps -o user= -p $(pgrep -f guest=VMNAME)`) — if running
     as a regular user, the VM was started under `qemu:///session` instead of
     `qemu:///system`. Destroy it and restart with `sudo virsh start VMNAME`.
  2. Does QEMU have `CAP_SYS_RAWIO`? (`grep CapEff /proc/$(pgrep -f guest=VMNAME)/status`)
     — CapEff should be non-zero. Zero means no capabilities → CAW/PR will always fail.
  3. Is QEMU using `scsi-block`? (`ps aux | grep guest=VMNAME | grep scsi-block`)
  4. Is AppArmor blocking it? (`dmesg | grep -i apparmor` on host)
  5. Is the host device `/dev/sdc` accessible? (`ls -la /dev/sdc`)
- "Miscompare": The data on disk changed between read and CAW — retry once (another
  node or process may have written). If it persists, the device doesn't support CAW.

Report the exact error output if CAW fails. Do not skip this step.

## Step 7: Load MXFS Module (runs on guest via SSH)

The expected version is in `/src/mxfs/VERSION` (currently `0.11.0`).

```
# Check if already loaded and correct version
if lsmod | grep -q mxfs; then
    LOADED_VER=$(modinfo mxfs 2>/dev/null | grep ^version | awk '{print $2}')
    EXPECTED_VER=$(cat /src/mxfs/VERSION)
    if [ "$LOADED_VER" = "$EXPECTED_VER" ]; then
        echo "ALREADY_LOADED version=$LOADED_VER"
    else
        echo "WRONG_VERSION loaded=$LOADED_VER expected=$EXPECTED_VER — reloading"
        rmmod mxfs
        sleep 1
    fi
fi

# Load if not loaded (or was just unloaded due to wrong version)
if ! lsmod | grep -q mxfs; then
    modprobe libcrc32c 2>/dev/null || true
    insmod /src/mxfs/mxfs.ko
fi

# Final verify
lsmod | grep -q mxfs || echo "LOAD_FAILED"
FINAL_VER=$(modinfo mxfs 2>/dev/null | grep ^version | awk '{print $2}')
echo "MODULE version=$FINAL_VER"
```

If the module fails to load, check dmesg for the error:
```
dmesg | tail -5
```

Report the dmesg output if load fails.

## Step 8: Install Benchmark Dependencies (runs on guest via SSH)

```
mkdir -p /mnt/shared
dpkg -l mosquitto-clients 2>/dev/null | grep -q '^ii' || (apt-get update -qq && apt-get install -y -qq mosquitto-clients)
dpkg -l fio 2>/dev/null | grep -q '^ii' || (apt-get update -qq && apt-get install -y -qq fio)
```

Create per-host benchmark directory (avoids root dir EX lock contention at high node counts):
```
mkdir -p /mnt/shared/$(hostname)
```

Verify MQTT broker connectivity:
```
mosquitto_pub -h 192.168.1.149 -t bench/test -m ping
```

If the broker is unreachable, report a warning but do not fail — MQTT is only needed for
synchronized multi-node benchmarks.

## Step 9: Report

Report back with this format:
```
VMNAME: PREP_OK device=DEVICE_PATH
```
or
```
VMNAME: PREP_FAIL step=N reason=DESCRIPTION
```

Include any warnings (e.g., "XML was fixed", "stale process killed", "NFS was remounted").

## Notes

- Do NOT mount the filesystem in this runbook. mkfs and mount are separate operations
  done by the Director after all nodes are prepped.
- Do NOT modify the mxfs source code or rebuild the module. That's done on the host.
- If `sg_compare_and_write` is not installed: `apt-get install -y sg3-utils`
- Multiple commands can be combined in a single SSH call to reduce round trips.
