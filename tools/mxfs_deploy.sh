#!/bin/bash
#
# Deploy MXFS to a remote node
# Usage: mxfs_deploy.sh <host> [--no-mount]
#
HOST="$1"
NOMOUNT="$2"
SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"
PF="/tmp/.mxfs_pass"
EXP="$SRCDIR/tools/mxfs_ssh.exp"

ssh_run() { $EXP "$HOST" "$PF" "$1"; }
scp_run() { $EXP "$HOST" "$PF" SCP "$1" "$2"; }

echo "=== Deploying to $HOST ==="

echo "--- Step 1: Unmount + unload module ---"
ssh_run "umount /mnt/shared 2>/dev/null; sleep 1; pkill -9 -f mxfsd 2>/dev/null; rmmod mxfs 2>/dev/null; rm -rf /root/mxfs/daemon /root/mxfs/kernel; mkdir -p /root/mxfs; echo CLEANUP_DONE"

echo "--- Step 2: Copy source ---"
scp_run "$SRCDIR/include" "/root/mxfs/"
scp_run "$SRCDIR/daemon" "/root/mxfs/"
scp_run "$SRCDIR/kernel" "/root/mxfs/"
scp_run "$SRCDIR/Makefile" "/root/mxfs/"
echo "COPY_DONE"

echo "--- Step 3: Compile ---"
ssh_run "cd /root/mxfs && make daemon 2>&1 && echo BUILD_DAEMON_OK || echo BUILD_DAEMON_FAIL"
ssh_run "cd /root/mxfs && make kernel 2>&1 && echo BUILD_KERNEL_OK || echo BUILD_KERNEL_FAIL"

echo "--- Step 4: Install ---"
ssh_run "cp /root/mxfs/daemon/mxfsd /usr/sbin/mxfsd && echo DAEMON_INSTALLED"
ssh_run "insmod /root/mxfs/kernel/mxfs.ko && echo MODULE_LOADED || echo MODULE_LOAD_FAILED"

if [ "$NOMOUNT" != "--no-mount" ]; then
    echo "--- Step 5: Mount ---"
    ssh_run "mkdir -p /mnt/shared && mount -t mxfs /dev/sdb /mnt/shared && echo MOUNT_OK || echo MOUNT_FAILED"
    ssh_run "mount | grep mxfs; dmesg | tail -5"
fi

echo "=== Deploy to $HOST COMPLETE ==="
