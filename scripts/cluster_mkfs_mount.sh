#!/bin/bash
# Fresh-mkfs from test1, mount on test1..testN.  Assumes nodes already prepped
# (use cluster_reset_n.sh first).  Per RULE 3 this lives in the source tree.
# Usage: cluster_mkfs_mount.sh <n>

set -u
N="${1:?node count required}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass

echo "=== mkfs from test1 ==="
"$SSH" 192.168.120.186 "$PF" '
  sudo dd if=/dev/zero of=/dev/sda bs=1M count=512 oflag=direct status=none
  sudo /src/mxfs/tools/mkfs_mxfs -f /dev/sda 2>&1 | tail -1
  sync
  sudo mount -t mxfs /dev/sda /mnt/shared && echo OK_test1
' 2>&1 | grep -v "^Warning\|^Unauth\|^If you" | tail -3

echo "=== mount test2..test$N in parallel ==="
for n in $(seq 2 "$N"); do
  ip=$(getent hosts test$n.vm.localdomain | awk '{print $1}')
  ( timeout 60 "$SSH" "$ip" "$PF" 'sudo mount -t mxfs /dev/sda /mnt/shared && echo OK' 2>&1 | grep OK | xargs -I{} printf "test$n %s\n" "{}" ) &
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
