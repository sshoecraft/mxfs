#!/bin/bash
#
# dio_stable_writes_read.sh — an O_DIRECT read of an MXFS file on a block
# device that reports stable writes.
#
# A device reports stable writes when its data must not change while a write
# is in flight: iSCSI with DataDigest=CRC32C, dm-integrity, T10 PI.  At mount
# the superblock inherits the flag and every regular file's mapping carries
# it, and xfs_file_dio_read then selects its bounce-read ops.  The rig's iSCSI
# sessions carry no digest, so no rig run has ever taken that branch.
#
# The block layer's own switch, /sys/block/<disk>/queue/stable_writes, puts a
# device in that state without changing the transport, so the read path is
# exactly the one a digest-enabled session takes.  The flag is read at mount,
# so the mount is cycled around the flip, with the options it had.
#
# Steps on NODE, whose MXFS is mounted at MNT:
#   1. record the mount (source, options) and the device's stable_writes;
#   2. unmount, set stable_writes=1, mount again with the same options;
#   3. write SIZE_MB of random data buffered, fsync, record its sha256;
#   4. drop the page cache, read it back with dd iflag=direct, compare;
#   5. unmount, restore stable_writes, mount again, remove the file.
# PASS: the direct read's sha256 matches and the node is still answering.
# A kernel oops ends the ssh session; the node's serial log then has it.
#
# Budget: 64 MiB written and read on the QNAP LUN, native XFS ~1 s each way,
# plus two mount cycles of an idle 2-node TCP mount (~5 s each) -> 60 s for
# the whole remote step, which is what STEP_TIMEOUT_S bounds.
#
# Usage: tests/dio_stable_writes_read.sh [node] [mountpoint] [size_mb]
#
set -u

NODE="${1:-test1}"
MNT="${2:-/mnt/shared}"
SIZE_MB="${3:-64}"
STEP_TIMEOUT_S=60

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$HERE/tools/mxfs_sshpass.sh"
EV="$HERE/tests/evidence/dio_stable_writes_read/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date +%T)] $*"; }

say "node=$NODE mnt=$MNT size=${SIZE_MB}MiB evidence=$EV"

timeout "$STEP_TIMEOUT_S" "$SSH" "$NODE" "bash -s" <<EOF
set -u
MNT=$MNT
SIZE_MB=$SIZE_MB
F=\$MNT/dio_stable_writes_read.\$\$
line=\$(awk -v m="\$MNT" '\$2 == m' /proc/mounts)
[ -n "\$line" ] || { echo "RESULT FAIL: nothing mounted at \$MNT"; exit 1; }
src=\$(echo "\$line" | awk '{print \$1}')
fstype=\$(echo "\$line" | awk '{print \$3}')
opts=\$(echo "\$line" | awk '{print \$4}')
disk=\$(lsblk -no PKNAME "\$(readlink -f "\$src")" | head -1)
[ -n "\$disk" ] || disk=\$(basename "\$(readlink -f "\$src")")
sw=/sys/block/\$disk/queue/stable_writes
echo "mount: src=\$src type=\$fstype opts=\$opts disk=\$disk"
echo "kernel: \$(uname -r)  module srcversion: \$(cat /sys/module/mxfs/srcversion 2>/dev/null)"
orig=\$(cat \$sw)
echo "stable_writes before: \$orig"

remount() {
    timeout 30 umount "\$MNT" || { echo "RESULT FAIL: umount rc=\$?"; exit 1; }
    echo "\$1" > \$sw || { echo "RESULT FAIL: cannot write \$sw"; exit 1; }
    timeout 30 mount -t "\$fstype" -o "\$opts" "\$src" "\$MNT" || { echo "RESULT FAIL: mount rc=\$?"; exit 1; }
    echo "remounted with stable_writes=\$(cat \$sw)"
}

remount 1
dmesg -C
head -c \$((SIZE_MB << 20)) /dev/urandom > /tmp/dio_swr.src
want=\$(sha256sum < /tmp/dio_swr.src | awk '{print \$1}')
dd if=/tmp/dio_swr.src of="\$F" bs=1M conv=fsync status=none || { echo "RESULT FAIL: write rc=\$?"; exit 1; }
sync; echo 3 > /proc/sys/vm/drop_caches
echo "direct read starting"
t0=\$(date +%s.%N)
got=\$(dd if="\$F" iflag=direct bs=1M status=none | sha256sum | awk '{print \$1}')
t1=\$(date +%s.%N)
echo "direct read done in \$(awk -v a="\$t0" -v b="\$t1" 'BEGIN{print b - a}') s"
echo "want=\$want"
echo "got =\$got"
dmesg | tail -40
rm -f "\$F" /tmp/dio_swr.src
remount "\$orig"
if [ "\$want" = "\$got" ]; then echo "RESULT PASS"; else echo "RESULT FAIL: checksum mismatch"; exit 1; fi
EOF
rc=$?
say "remote step rc=$rc"
if [ "$rc" -ne 0 ]; then
    say "node answering: $(timeout 10 "$SSH" "$NODE" 'uptime' 2>&1 || echo NO)"
    log=/var/log/libvirt/qemu/$NODE-serial.log
    # libvirt writes it root-only
    say "serial log tail ($log):"
    sudo -n tail -80 "$log"
fi
exit $rc
