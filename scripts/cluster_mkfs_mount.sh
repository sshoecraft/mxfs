#!/bin/bash
# Fresh-mkfs from test1, mount on test1..testN.  Assumes nodes already prepped
# (use cluster_reset_n.sh first).  Per the source-tree rule this lives in the source tree.
# Usage: cluster_mkfs_mount.sh <n>

set -u
N="${1:?node count required}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass
MXFS_DEV=${MXFS_DEV:?the shared LUN as this rig names it. This script predates tests/lib/rig.sh and takes the device it is given without an identity check}

echo "=== mkfs from test1 ==="
"$SSH" 192.168.120.186 "$PF" '
  sudo dd if=/dev/zero of=$MXFS_DEV bs=1M count=512 oflag=direct status=none
  sudo /src/mxfs/tools/mkfs_mxfs -f $MXFS_DEV 2>&1 | tail -1
  sync
  sudo mount -t mxfs $MXFS_DEV /mnt/shared && echo OK_test1
' 2>&1 | grep -v "^Warning\|^Unauth\|^If you" | tail -3

echo "=== mount test2..test$N in parallel ==="
for n in $(seq 2 "$N"); do
  ip=$(getent hosts test$n.vm.localdomain | awk '{print $1}')
  ( timeout 60 "$SSH" "$ip" "$PF" 'sudo mount -t mxfs '"$MXFS_DEV"' /mnt/shared && echo OK' 2>&1 | grep OK | xargs -I{} printf "test$n %s\n" "{}" ) &
done
wait 2>/dev/null

echo "=== verify all $N mounted ==="
all=1
for n in $(seq 1 "$N"); do
  ip=$(getent hosts test$n.vm.localdomain | awk '{print $1}')
  m=$(timeout 4 "$SSH" "$ip" "$PF" 'mount | grep -c "/mnt/shared.*mxfs"' 2>/dev/null | tail -1 | tr -d "\r\n ")
  if [ "$m" != "1" ]; then
    printf "test%-2s NOT_MOUNTED\n" "$n"
    all=0
  fi
done
[ "$all" = "1" ] && echo "ALL_MOUNTED" || { echo "MOUNT_FAIL"; exit 1; }
