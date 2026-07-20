#!/bin/bash
# MXFS Node Prep Script — run ON the node itself
# Usage: prep_node.sh
# Returns: exit 0 + prints PREP_OK, or exit 1 + prints PREP_FAIL

ISCSI_TARGET="192.168.120.1:3260"
NFS_SERVER="192.168.1.4:/src"
NFS_MOUNT="/src"
MODULE="/src/mxfs/mxfs.ko"
DEVICE=""  # auto-detected after iSCSI login

fail() { echo "PREP_FAIL: $1"; exit 1; }

# 0. Random stagger (0-5s) so 32 nodes don't hit iSCSI at the same instant
sleep $((RANDOM % 6))

# 1. Cleanup
umount /mnt/shared 2>/dev/null || true
rmmod mxfs 2>/dev/null || true
sleep 1

# 2. NFS
if ! mountpoint -q "$NFS_MOUNT"; then
    mount -t nfs "$NFS_SERVER" "$NFS_MOUNT" -o rw,vers=3,soft,timeo=100,retrans=5,tcp,rsize=1048576,wsize=1048576,async,noatime,nodiratime || fail "NFS mount failed"
fi
[ -f "$MODULE" ] || fail "Module not found at $MODULE"

# 3. iSCSI (with timeouts to prevent hanging)
timeout 5 iscsiadm -m node -u all 2>/dev/null || true
timeout 5 iscsiadm -m node -o delete 2>/dev/null || true
sleep 1
timeout 15 iscsiadm -m discovery -t st -p "$ISCSI_TARGET" 2>/dev/null || fail "iSCSI discovery failed/timeout"
timeout 15 iscsiadm -m node --login 2>/dev/null || fail "iSCSI login failed/timeout"
sleep 2

# 3b. Multipath is EXPECTED in production: enterprise SANs present redundant
#     fabric paths and multipathd coalesces them into /dev/mapper/mpathX, which
#     is the device you mount.  Do NOT disable it — MXFS must run on the mpath
#     device.  (The *spurious* extra paths seen in the lab came from clyde
#     advertising the target on all its bridge IPs; that is pinned to the SAN
#     network via SCST allowed_portal, so we get the correct path topology.)
#     Give multipathd a moment to assemble the path(s); section 4 prefers mpath.
sleep 3

# 4. Detect the shared device.  PREFER the multipath device — production SANs
#    are multipathed and /dev/mapper/mpathX is the correct device to mount (and
#    is what MXFS's CAW must work through).  Fall back to the raw iSCSI disk only
#    if multipathd is not managing it (e.g. a genuinely single-path test host).
for mp in /dev/mapper/mpath*; do
    [ -b "$mp" ] || continue
    DEVICE="$mp"; break
done
[ -n "$DEVICE" ] || \
for dev in /dev/sda /dev/sdb /dev/sdc; do
    if [ -b "$dev" ]; then
        # Check it's a SCSI disk (not virtio boot disk)
        if lsblk -ndo TRAN "$dev" 2>/dev/null | grep -q iscsi; then
            DEVICE="$dev"
            break
        fi
        # Fallback: check if it's NOT the boot disk
        if ! lsblk -n "$dev" 2>/dev/null | grep -qE 'part|lvm'; then
            DEVICE="$dev"
            break
        fi
    fi
done
[ -n "$DEVICE" ] || fail "Could not find iSCSI block device"
[ -b "$DEVICE" ] || fail "iSCSI device $DEVICE not found"
chmod 666 "$DEVICE" 2>/dev/null

# 5. Load module
modprobe libcrc32c 2>/dev/null || true
insmod "$MODULE" 2>/dev/null || true
lsmod | grep -q mxfs || fail "mxfs module not loaded"

# 6. Verify readable
dd if="$DEVICE" of=/dev/null bs=1M count=1 2>/dev/null || fail "Cannot read $DEVICE"

echo "PREP_OK device=$DEVICE"
exit 0
