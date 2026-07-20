#!/bin/bash
# MXFS TCM Loop Node Prep Script — run ON the node itself
# Usage: prep_tcm_node.sh
# Returns: exit 0 + prints PREP_OK, or exit 1 + prints PREP_FAIL
#
# Shared SCSI LUN is presented by the SCST iscsi target (vdisk_fileio,
# write_through) and reaches the VM as a normal SCSI disk.  SCST's vdisk
# implements SCSI COMPARE AND WRITE (CAW, opcode 0x89) natively, which is
# why MXFS CAW coordination works on this stack (the old LIO iblock stack
# did not honor CAW reliably).  Device identifies as vendor "SCST_FIO".

NFS_SERVER="192.168.1.4:/src"
NFS_MOUNT="/src"
MODULE="/src/mxfs/mxfs.ko"
DEVICE=""

fail() { echo "PREP_FAIL: $1"; exit 1; }

# 1. Cleanup — unmount mxfs and unload module
umount /mnt/shared 2>/dev/null || true
rmmod mxfs 2>/dev/null || true
sleep 1

# 2. NFS
if ! mountpoint -q "$NFS_MOUNT"; then
    mkdir -p "$NFS_MOUNT"
    mount -t nfs "$NFS_SERVER" "$NFS_MOUNT" -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp,rsize=1048576,wsize=1048576 || fail "NFS mount failed"
fi
[ -f "$MODULE" ] || fail "Module not found at $MODULE"

# 3. Find the shared SCST SCSI device (vendor SCST_FIO, model disk1/disk2)
for dev in /dev/sda /dev/sdb /dev/sdc; do
    [ -b "$dev" ] || continue
    vendor=$(cat /sys/block/$(basename $dev)/device/vendor 2>/dev/null | tr -d ' ')
    if [ "$vendor" = "SCST_FIO" ]; then
        DEVICE="$dev"
        break
    fi
done
[ -n "$DEVICE" ] || fail "Could not find SCST_FIO shared device"

# 3b. Widen the SCSI command timeout (Linux default 30s) to 180s.  THE WEDGE
#     PREVENTION (sess68, run 14d31183).  A strictly-serialized SCST command —
#     CAW (0x89) or mkfs's WRITE SAME slot-table zero — held longer than the
#     guest's SCSI command timeout while the target drains outstanding commands
#     under 16-node load makes the guest SCSI error handler fire ABORT_TASK ->
#     LUN_RESET -> I_T nexus loss.  Each nexus loss leaks an uninterruptible
#     iscsi_conn_cleanup kthread on the target that pins the device's command
#     refcount forever, so EVERY later serialized command blocks in
#     EXEC_CHECK_BLOCKING and the shared LUN is PERMANENTLY wedged for all nodes
#     (proven sess14; recurred sess15/sess67/sess68 — each needed a host reset,
#     which RULE 2 reserves for the user).  The measured guest timeout here was
#     30s — far too tight for a transiently-deep CAW serialization queue.  180s
#     lets a slow-but-progressing command finish instead of escalating.  This
#     does NOT mask mxfs slowness: the per-iter test budget (RULE 0) still fails
#     a genuinely slow run; this only stops a transient transport stall from
#     converting into an unrecoverable host wedge.
echo 180 > "/sys/block/$(basename "$DEVICE")/device/timeout" 2>/dev/null || true

# 4. Verify CAW support — NON-DESTRUCTIVELY.
#    Do NOT issue a real sg_compare_and_write self-test here: it writes to a
#    fixed LBA and SCST (which enforces SCSI Persistent Reservations) returns
#    a Reservation Conflict whenever the LUN already carries a reservation —
#    i.e. on every joiner node (the forming node holds WRITE-EXCLUSIVE,
#    REGISTRANTS-ONLY and a joiner isn't registered until mxfs mount runs),
#    and on cold starts with a stale key from a dead node.  That self-test
#    therefore broke multi-node mount.  sg_opcodes asks the device which
#    commands it supports (a read), confirming COMPARE AND WRITE (0x89)
#    without writing anything or tripping PR.
if ! sg_opcodes "$DEVICE" 2>/dev/null | grep -qi "compare and write"; then
    fail "Device $DEVICE does not advertise SCSI COMPARE AND WRITE (0x89)"
fi

# 5. Load module
modprobe libcrc32c 2>/dev/null || true
insmod "$MODULE" 2>/dev/null || true
lsmod | grep -q mxfs || fail "mxfs module not loaded"

# 6. Create mount point
mkdir -p /mnt/shared

echo "PREP_OK device=$DEVICE"
exit 0
