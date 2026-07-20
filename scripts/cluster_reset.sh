#!/bin/bash
# Sess23: hard reset of MXFS cluster with retry on transient rmmod-busy.
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass
T1=192.168.120.186
T2=192.168.120.182

run() { "$SSH" "$1" "$PF" "$2" 2>&1 | grep -vE '^Warning|^Unauthorized|^If you'; }

unload() {
  local N=$1
  run "$N" '
    sudo umount -f /mnt/shared 2>/dev/null
    sudo umount -l /mnt/shared 2>/dev/null
    sleep 2
    for i in 1 2 3 4 5 6 7 8; do
      if ! lsmod | grep -q "^mxfs "; then
        echo UNLOAD_OK_try$i
        exit 0
      fi
      if sudo rmmod mxfs 2>/dev/null; then
        echo UNLOAD_OK_try$i
        exit 0
      fi
      sleep 10
    done
    echo "UNLOAD_FAIL refcnt=$(cat /sys/module/mxfs/refcnt 2>/dev/null) lsmod=$(lsmod | grep mxfs)"
    exit 1
  '
}

echo "=== T2 unload ==="
unload "$T2"
echo "=== T1 unload ==="
unload "$T1"

echo "=== T1 insmod + mkfs + mount ==="
run "$T1" "sudo insmod /mnt/mxfs-src/mxfs.ko && echo T1_INSMOD_OK; sudo /mnt/mxfs-src/tools/mkfs_mxfs -f /dev/sda > /tmp/mkfs.log 2>&1 && echo T1_MKFS_OK; sudo blockdev --flushbufs /dev/sda; sync; sleep 1; sudo mount -t mxfs /dev/sda /mnt/shared 2>&1 && echo T1_MOUNT_OK || (echo MOUNT_FAIL; cat /tmp/mkfs.log)"

echo "=== T2 insmod + mount ==="
run "$T2" "sudo insmod /mnt/mxfs-src/mxfs.ko && echo T2_INSMOD_OK; sleep 1; sudo mount -t mxfs /dev/sda /mnt/shared && echo T2_MOUNT_OK"

echo "=== Final state ==="
run "$T1" "lsmod | grep mxfs; mount | grep '/mnt/shared'"
echo "---"
run "$T2" "lsmod | grep mxfs; mount | grep '/mnt/shared'"
