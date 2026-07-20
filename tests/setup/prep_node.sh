#!/bin/bash
# MXFS node OS-infra prep — run ON every node that will participate.
#
# Config-layer script (not a test): makes the node's OS ready for MXFS and
# leaves the filesystem MOUNTED at the mount point.  Owns the transport choice
# (this is the config layer); the FS test suite never sees it.
#
# Run AFTER prep_fs.sh has mkfs'd the shared LUN (mount needs a formatted FS).
#
# Usage (on the node):  tests/setup/prep_node.sh [tcp|caw]
#   tcp (default) -> insmod mxfs.ko force_transport=1   (works on LIO or SCST)
#   caw           -> insmod mxfs.ko                     (auto/CAW; needs SCST)
# Env (defaults):
#   MXFS_REPO /src/mxfs   MXFS_DEV /dev/sda   MXFS_MOUNT /mnt/shared
#   NFS_SERVER 192.168.1.4:/src   NFS_MOUNT /src   SCSI_TIMEOUT 180
#
# Prints NODE_PREP_OK on success, NODE_PREP_FAIL: <reason> + exit 1 otherwise.

set -u

TRANSPORT="${1:-tcp}"
MXFS_REPO="${MXFS_REPO:-/src/mxfs}"
MXFS_DEV="${MXFS_DEV:-/dev/sda}"
MXFS_MOUNT="${MXFS_MOUNT:-/mnt/shared}"
NFS_SERVER="${NFS_SERVER:-192.168.1.4:/src}"
NFS_MOUNT="${NFS_MOUNT:-/src}"
SCSI_TIMEOUT="${SCSI_TIMEOUT:-180}"
MODULE="$MXFS_REPO/mxfs.ko"

fail() { echo "NODE_PREP_FAIL: $*" >&2; exit 1; }

case "$TRANSPORT" in
    tcp) MODARGS="force_transport=1" ;;
    caw) MODARGS="" ;;
    *)   fail "unknown transport '$TRANSPORT' (expect tcp|caw)" ;;
esac

# 1. NFS /src (idempotent) — source of mxfs.ko.
if ! mountpoint -q "$NFS_MOUNT"; then
    mkdir -p "$NFS_MOUNT"
    mount -t nfs "$NFS_SERVER" "$NFS_MOUNT" \
        -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp,rsize=1048576,wsize=1048576 \
        || fail "NFS mount $NFS_SERVER -> $NFS_MOUNT failed"
fi
[ -f "$MODULE" ] || fail "module not found at $MODULE"

# 2. Test-dependency tools (best-effort — don't fail prep if apt is offline).
for pkg in fio mosquitto-clients sg3-utils attr; do
    dpkg -l "$pkg" 2>/dev/null | grep -q '^ii' || apt-get install -y -qq "$pkg" >/dev/null 2>&1 || \
        echo "WARN: could not ensure package $pkg"
done

# 3. Clean slate: unmount + unload any prior MXFS on this node.
#    A shut-down/self-fenced leftover mount won't yield to a plain umount, so
#    fall back to lazy umount, then retry rmmod (the module can be briefly busy
#    right after umount, or held by a draining worker).  Leaving a stale mount +
#    OLD module up here is exactly what made run.sh's readiness check pass on a
#    mismatched build (invalid test result) — refuse to proceed unless we truly
#    end up with NO mxfs module loaded.
if mountpoint -q "$MXFS_MOUNT"; then
    # Kill leftover test processes first — a busy mount survives plain and
    # forced umount alike.  A shut-down/self-fenced FS returns EIO to a plain
    # umount; umount -f (force) tears it down, then -l (lazy) as a last resort.
    fuser -km "$MXFS_MOUNT" 2>/dev/null; sleep 1
    umount "$MXFS_MOUNT" 2>/dev/null \
        || timeout 25 umount -f "$MXFS_MOUNT" 2>/dev/null \
        || umount -l "$MXFS_MOUNT" 2>/dev/null || true
fi
if lsmod | grep -q '^mxfs'; then
    for i in 1 2 3 4 5 6 7 8; do
        rmmod mxfs 2>/dev/null && break
        sleep 2
    done
    lsmod | grep -q '^mxfs' && fail "mxfs module loaded and won't rmmod after retries (wedged?)"
fi

# 4. Load the module with the chosen transport.
modprobe libcrc32c 2>/dev/null || true
insmod "$MODULE" $MODARGS ${MXFS_EXTRA_MODARGS:-} || fail "insmod $MODULE $MODARGS ${MXFS_EXTRA_MODARGS:-} failed"
lsmod | grep -q '^mxfs' || fail "mxfs not loaded after insmod"

# 4a2. Catch in-guest wedges with stacks: run21 had a 112s whole-node stall
#      that khungtaskd's default 120s window just missed.  30s + all-cpu
#      backtraces names the blocked thread if it recurs.
echo 30 > /proc/sys/kernel/hung_task_timeout_secs 2>/dev/null || true
echo 1 > /proc/sys/kernel/hung_task_all_cpu_backtrace 2>/dev/null || true

# 4b. Stream the kernel log to a file so diagnostic probe output survives ring
#     rollover (sess4 a16ec5f2: a dirwr run emits ~17MB/node and the ring lost
#     the failing round entirely).  Survives this SSH session via setsid.
pkill -f 'dmesg --follow' 2>/dev/null || true
rm -f /root/dmesg.stream
setsid bash -c 'exec dmesg --follow > /root/dmesg.stream 2>&1 < /dev/null' &
sleep 0.2
pgrep -f 'dmesg --follow' >/dev/null || echo "WARN: dmesg stream capture not running"

# 5. Widen the guest SCSI command timeout (sess68 nexus-loss wedge prevention).
#    /dev/mapper/* is a symlink to /dev/dm-N — resolve it, and for a dm device
#    widen the timeout on every underlying SCSI path instead (dm itself has no
#    SCSI command timeout).
DEVNAME=$(basename "$(readlink -f "$MXFS_DEV")")
if [ -w "/sys/block/$DEVNAME/device/timeout" ]; then
    echo "$SCSI_TIMEOUT" > "/sys/block/$DEVNAME/device/timeout" 2>/dev/null \
        || echo "WARN: could not set $DEVNAME cmd timeout"
elif [ -d "/sys/block/$DEVNAME/slaves" ]; then
    for sl in "/sys/block/$DEVNAME/slaves"/*; do
        [ -w "$sl/device/timeout" ] || continue
        echo "$SCSI_TIMEOUT" > "$sl/device/timeout" 2>/dev/null \
            || echo "WARN: could not set $(basename "$sl") cmd timeout"
    done
fi

# 5b. Invalidate this node's stale block-device buffer cache for the shared LUN
#     BEFORE mounting.  The bdev page/buffer cache survives umount+rmmod, so on a
#     second consecutive run (no VM reboot) the non-reformatting peers still hold
#     OLD-filesystem pages for /dev/sda.  test1 re-mkfs'd the LUN with fresh
#     content, but those peers would mount on top of stale cached metadata ->
#     round-1 dir incoherence / DABUF-HOLE corruption.  BLKFLSBUF flushes dirty
#     buffers then INVALIDATES the cache so the new mount reads the fresh LUN.
blockdev --flushbufs "$MXFS_DEV" 2>/dev/null || echo "WARN: blockdev --flushbufs $MXFS_DEV failed"

# 6. Mount the FS.
mkdir -p "$MXFS_MOUNT"
mount -t mxfs "$MXFS_DEV" "$MXFS_MOUNT" || fail "mount -t mxfs $MXFS_DEV $MXFS_MOUNT failed"
mountpoint -q "$MXFS_MOUNT" || fail "$MXFS_MOUNT not mounted after mount"

echo "NODE_PREP_OK transport=$TRANSPORT dev=$MXFS_DEV mount=$MXFS_MOUNT timeout=$(cat /sys/block/$DEVNAME/device/timeout 2>/dev/null)"
