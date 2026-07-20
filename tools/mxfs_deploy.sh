#!/bin/bash
#
# Deploy MXFS to a remote node via NFS
# Usage: mxfs_deploy.sh <host> [--no-mount]
#
# Assumes the node has NFS-mounted /mnt/mxfs-src from the dev machine.
# Builds on the remote node (target kernel), loads the module, and
# optionally mounts the shared filesystem.
#
HOST="$1"
NOMOUNT="$2"
SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"
PF="/tmp/.mxfs_pass"
SSH="$SRCDIR/tools/mxfs_sshpass.sh"
NFS_DST="/mnt/mxfs-src"

ssh_run() { "$SSH" "$HOST" "$PF" "$1"; }

echo "=== Deploying to $HOST ==="

echo "--- Step 1: Unmount + unload module ---"
ssh_run "umount /mnt/shared 2>/dev/null; sleep 1; rmmod mxfs 2>/dev/null; echo CLEANUP_DONE"

echo "--- Step 2: Ensure NFS mount ---"
ssh_run "mountpoint -q ${NFS_DST} 2>/dev/null || { sudo mkdir -p ${NFS_DST}; sudo mount -t nfs 192.168.120.1:/src/mxfs ${NFS_DST}; }; echo NFS_OK"

echo "--- Step 3: Load prerequisites ---"
ssh_run "modprobe libcrc32c 2>/dev/null; echo MODPROBE_DONE"

echo "--- Step 4: Build on target ---"
ssh_run "cd ${NFS_DST} && make clean && make 2>&1 && echo BUILD_OK || echo BUILD_FAIL"

echo "--- Step 5: Load module ---"
ssh_run "insmod ${NFS_DST}/mxfs.ko && echo MODULE_LOADED || echo MODULE_LOAD_FAILED"

if [ "$NOMOUNT" != "--no-mount" ]; then
    echo "--- Step 6: Mount ---"
    ssh_run "mkdir -p /mnt/shared && mount -t mxfs /dev/sda /mnt/shared && echo MOUNT_OK || echo MOUNT_FAILED"
    ssh_run "mount | grep mxfs; dmesg | tail -5"
fi

echo "=== Deploy to $HOST COMPLETE ==="
